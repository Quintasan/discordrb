# frozen_string_literal: true

require 'discordrb/logger'
require 'discordrb/voice/opcodes'
require_relative '../dave'
require_relative 'session'

module Discordrb::Voice
  module DAVE
    # Handles the DAVE part of the voice gateway protocol for a single voice connection.
    #
    # It keeps the MLS session in sync with the voice gateway (key packages, proposals, commits and welcomes), answers
    # the gateway's transition messages, and encrypts the outgoing audio frames.
    #
    # @!visibility private
    class Handler
      # @return [Integer] the DAVE protocol version negotiated with the voice gateway, 0 if DAVE is not in use
      attr_reader :protocol_version

      # @return [Integer, nil] the SSRC of this connection, used to encrypt audio frames
      attr_accessor :ssrc

      # @param channel_id [Integer] The ID of the voice channel, used as the MLS group ID
      # @param self_user_id [Integer, String] The ID of the user this connection belongs to
      # @param send_json [#call] Called with an opcode and a hash to send a JSON message to the voice gateway
      # @param send_binary [#call] Called with an opcode and a binary string to send a binary message to the gateway
      # @param session_factory [#call, nil] Creates the DAVE session, replaceable for testing
      def initialize(channel_id:, self_user_id:, send_json:, send_binary:, session_factory: nil)
        @channel_id = channel_id.to_i
        @self_user_id = self_user_id.to_s
        @send_json = send_json
        @send_binary = send_binary
        @session_factory = session_factory || -> { Session.new(@self_user_id) }

        @protocol_version = 0
        @recognized_users = {}
        @external_sender = nil
        @pending_transition_id = nil
        @session = nil
        @needs_key_package = false
        @encryptor = nil
        @key_ratchet = nil
        @closed = false
      end

      # Handles a JSON message from the voice gateway.
      # @param opcode [Integer]
      # @param data [Hash, nil]
      def handle_json(opcode, data)
        return if @closed

        data ||= {}
        case opcode
        when Opcodes::CLIENT_CONNECT
          Array(data['user_ids']).each { |user_id| add_recognized_user(user_id) }
        when Opcodes::CLIENT_DISCONNECT
          remove_recognized_user(data['user_id'])
        when Opcodes::SESSION_DESCRIPTION
          negotiate_protocol_version(data['dave_protocol_version'].to_i)
        when Opcodes::DAVE_PREPARE_TRANSITION
          prepare_transition(data['protocol_version'].to_i, data['transition_id'].to_i)
        when Opcodes::DAVE_EXECUTE_TRANSITION
          execute_transition(data['transition_id'].to_i)
        when Opcodes::DAVE_PREPARE_EPOCH
          prepare_epoch(data['protocol_version'].to_i, data['epoch'].to_i)
        when Opcodes::DAVE_MLS_INVALID_COMMIT_WELCOME
          invalid_commit_welcome
        end
      end

      # Handles a binary message from the voice gateway. The sequence number must already be stripped off.
      # @param opcode [Integer]
      # @param payload [String] the rest of the message
      def handle_binary(opcode, payload)
        return if @closed

        case opcode
        when Opcodes::DAVE_MLS_EXTERNAL_SENDER
          handle_external_sender(payload)
        when Opcodes::DAVE_MLS_PROPOSALS
          process_proposals(payload)
        when Opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION
          transition_id, commit = Framing.split_transition(payload)
          process_commit(transition_id, commit)
        when Opcodes::DAVE_MLS_WELCOME
          transition_id, welcome = Framing.split_transition(payload)
          process_welcome(transition_id, welcome)
        end
      end

      # Encrypts one audio frame, if this connection takes part in an established group.
      # @param frame [String] one Opus frame
      # @return [String, nil] the frame to send, unchanged while in passthrough mode, or `nil` if it must be dropped
      #   because it could not be encrypted
      def encrypt_audio(frame)
        return frame if @closed

        target = encryptor
        return frame if target.nil? || target.passthrough?

        target.encrypt(frame, @ssrc)
      end

      # Releases the session, the encryptor and the key ratchet.
      def close
        return if @closed

        @closed = true
        @encryptor&.destroy
        @encryptor = nil
        @key_ratchet&.destroy
        @key_ratchet = nil
        @session&.destroy
        @session = nil
      end

      private

      # The DAVE session, created on first use.
      def session
        return @session if @session

        @session = @session_factory.call
        @recognized_users.each_key { |user_id| @session.add_recognized_user(user_id) }
        @session
      end

      def encryptor
        return @encryptor if @encryptor
        return nil unless @ssrc

        @encryptor = Encryptor.new(@ssrc)
      end

      def add_recognized_user(user_id)
        user_id = user_id.to_s
        return if user_id.empty? || @recognized_users.key?(user_id)

        @recognized_users[user_id] = true
        @session&.add_recognized_user(user_id)
      end

      def remove_recognized_user(user_id)
        user_id = user_id.to_s
        return unless @recognized_users.delete(user_id)

        @session&.remove_recognized_user(user_id)
      end

      # The gateway picked a DAVE protocol version for this connection. A non-zero version means that a key package
      # has to be offered for the group that is about to be created.
      def negotiate_protocol_version(protocol_version)
        @protocol_version = protocol_version
        return if protocol_version.zero?

        reset_group(protocol_version)
      end

      # The gateway announces a new epoch. Epoch 1 means that every member has to drop its group and start a new one.
      def prepare_epoch(protocol_version, epoch)
        @protocol_version = protocol_version
        if epoch <= 1 || @session.nil?
          reset_group(protocol_version)
        else
          @session.protocol_version = protocol_version
        end
      end

      # Drops the local group state, creates a new pending group and offers a fresh key package to the gateway.
      def reset_group(protocol_version)
        @session&.destroy
        @session = nil
        @needs_key_package = true

        # The old key ratchets are worthless as soon as the group is dropped, so the connection passes frames
        # through unencrypted until the new group is established.
        @key_ratchet&.destroy
        @key_ratchet = nil
        @encryptor&.passthrough = true

        target = session
        target.init(protocol_version, @channel_id)
        @recognized_users.each_key { |user_id| target.add_recognized_user(user_id) }
        target.external_sender = @external_sender if @external_sender

        send_key_package
      end

      # The voice gateway is the external sender of the group, which every member needs before it can create one.
      def handle_external_sender(package)
        already_known = package == @external_sender
        @external_sender = package
        return if @session.nil?
        # libdave only accepts the external sender before the group exists, and ignores a repeated one
        return if already_known

        @session.external_sender = package
        send_key_package
      end

      # Offers a key package to the gateway, which is only possible once the external sender is known.
      def send_key_package
        return unless @protocol_version.positive? && @needs_key_package && @external_sender && @session

        @needs_key_package = false
        key_package = @session.marshalled_key_package
        return if key_package.nil? || key_package.empty?

        DAVE.logger.debug("Sending DAVE key package (#{key_package.bytesize} bytes)")
        @send_binary.call(Opcodes::DAVE_MLS_KEY_PACKAGE, key_package)
      end

      def process_proposals(payload)
        return if @session.nil?

        commit_welcome = @session.process_proposals(payload)
        return if commit_welcome.nil? || commit_welcome.empty?

        DAVE.logger.debug("Sending DAVE commit and welcome (#{commit_welcome.bytesize} bytes)")
        @send_binary.call(Opcodes::DAVE_MLS_COMMIT_WELCOME, commit_welcome)
      end

      def process_commit(transition_id, commit)
        return if @session.nil?

        result = @session.process_commit(commit)
        return if result.nil?

        begin
          return invalid_transition(transition_id) if result.failed?
          return if result.ignored?

          transition_ready(transition_id)
        ensure
          result.destroy
        end
      end

      def process_welcome(transition_id, welcome)
        return if @session.nil?

        if @session.process_welcome(welcome)
          transition_ready(transition_id)
        else
          invalid_transition(transition_id)
        end
      end

      # The gateway prepares a protocol version transition. Transition 0 is executed right away without an answer.
      def prepare_transition(protocol_version, transition_id)
        @protocol_version = protocol_version
        if transition_id.zero?
          apply_transition
        else
          @pending_transition_id = transition_id
          transition_ready(transition_id)
        end
      end

      def execute_transition(transition_id)
        if @pending_transition_id != transition_id
          DAVE.logger.debug("Executing DAVE transition #{transition_id} without having prepared " \
                            "#{@pending_transition_id}")
        end

        @pending_transition_id = nil
        apply_transition
      end

      # Switches the outgoing audio to the key ratchet of the new epoch, or to passthrough mode for version 0.
      def apply_transition
        target = encryptor
        return if target.nil?

        if @protocol_version.zero?
          target.passthrough = true
          @key_ratchet&.destroy
          @key_ratchet = nil
          return
        end

        ratchet = @session&.key_ratchet(@self_user_id)
        if ratchet.nil?
          target.passthrough = true
          return
        end

        @key_ratchet&.destroy
        @key_ratchet = ratchet
        target.key_ratchet = ratchet
        target.passthrough = false
      end

      def transition_ready(transition_id)
        @send_json.call(Opcodes::DAVE_TRANSITION_READY, { transition_id: transition_id })
      end

      def invalid_transition(transition_id)
        DAVE.logger.debug("Rejecting DAVE transition #{transition_id}")
        @send_json.call(Opcodes::DAVE_MLS_INVALID_COMMIT_WELCOME, { transition_id: transition_id })
      end

      # The gateway rejected a message we sent, so we drop our group state and offer a new key package.
      def invalid_commit_welcome
        DAVE.logger.warn('The voice gateway rejected a DAVE commit or welcome, resetting the MLS group')
        reset_group(@protocol_version)
      end
    end
  end
end
