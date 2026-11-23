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
      attr_reader :ssrc

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
        @pending_protocol_version = nil
        @session = nil
        @needs_key_package = false
        @encryptor = nil
        @key_ratchet = nil
        @closed = false
        @encryption_established = false
        @dropping_frames = false

        # The gateway messages arrive on the voice websocket thread, the audio frames on the thread that plays them.
        @lock = Mutex.new
      end

      # @param value [Integer, nil] the SSRC of this connection, used to encrypt audio frames
      def ssrc=(value)
        @lock.synchronize do
          @ssrc = value
          @encryptor&.ssrc = value
        end
      end

      # Handles a JSON message from the voice gateway.
      # @param opcode [Integer]
      # @param data [Hash, nil]
      def handle_json(opcode, data)
        @lock.synchronize { process_json(opcode, data) }
      end

      # Handles a binary message from the voice gateway. The sequence number must already be stripped off.
      # @param opcode [Integer]
      # @param payload [String] the rest of the message
      def handle_binary(opcode, payload)
        @lock.synchronize { process_binary(opcode, payload) }
      end

      # Encrypts one audio frame, if this connection takes part in an established group.
      # @param frame [String] one Opus frame
      # @return [String, nil] the frame to send, unchanged while in passthrough mode, or `nil` if it must be dropped
      #   because it could not be encrypted
      def encrypt_audio(frame)
        @lock.synchronize do
          return frame if @closed
          return nil if @dropping_frames

          target = encryptor
          return frame if target.nil? || target.passthrough?

          target.encrypt(frame, @ssrc)
        end
      end

      # Releases the session, the encryptor and the key ratchet.
      def close
        @lock.synchronize do
          return if @closed

          @closed = true
          @encryptor&.destroy
          @encryptor = nil
          @key_ratchet&.destroy
          @key_ratchet = nil
          @session&.destroy
          @session = nil
        end
      end

      private

      # Handles a JSON message from the voice gateway.
      def process_json(opcode, data)
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
        end
      end

      # Handles a binary message from the voice gateway.
      def process_binary(opcode, payload)
        return if @closed

        case opcode
        when Opcodes::DAVE_MLS_EXTERNAL_SENDER
          handle_external_sender(payload)
        when Opcodes::DAVE_MLS_PROPOSALS
          process_proposals(payload)
        when Opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION
          transition_id, commit = split_transition(payload)
          process_commit(transition_id, commit) if transition_id
        when Opcodes::DAVE_MLS_WELCOME
          transition_id, welcome = split_transition(payload)
          process_welcome(transition_id, welcome) if transition_id
        end
      end

      # Splits the transition ID off a DAVE payload, dropping messages that are too short to carry one.
      # @return [Array(Integer, String), nil]
      def split_transition(payload)
        Framing.split_transition(payload)
      rescue ArgumentError => e
        DAVE.logger.warn("Ignoring a malformed DAVE message: #{e.message}")
        nil
      end

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

        # The old key ratchets are worthless as soon as the group is dropped. A connection that has already
        # encrypted media drops its frames until the new group is established instead of sending them in the clear,
        # because the call is still end-to-end encrypted for everyone else.
        @key_ratchet&.destroy
        @key_ratchet = nil
        @encryptor&.passthrough = true
        @dropping_frames = @encryption_established

        target = session
        target.init(protocol_version, @channel_id)
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

        key_package = @session.marshalled_key_package
        return if key_package.nil? || key_package.empty?

        @needs_key_package = false
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

        # Read the result and release it before the session state is touched, because resetting the group drops the
        # session that the result came from.
        begin
          failed = result.failed?
          ignored = result.ignored?
        ensure
          result.destroy
        end

        return invalid_transition(transition_id) if failed
        return if ignored

        finish_transition(transition_id)
      end

      def process_welcome(transition_id, welcome)
        return if @session.nil?

        if @session.process_welcome(welcome)
          finish_transition(transition_id)
        else
          invalid_transition(transition_id)
        end
      end

      # The gateway prepares a protocol version transition. Transition 0 is executed right away without an answer.
      def prepare_transition(protocol_version, transition_id)
        @pending_transition_id = transition_id
        @pending_protocol_version = protocol_version

        if transition_id.zero?
          execute_transition(transition_id)
        else
          transition_ready(transition_id)
        end
      end

      # Transition 0 is the very first epoch, which the gateway executes without asking. Every later transition is
      # acknowledged and executed when the gateway sends the execute message.
      def finish_transition(transition_id)
        # A commit or welcome can arrive without a prepared transition, for example for the very first epoch.
        if @pending_transition_id != transition_id
          @pending_transition_id = transition_id
          @pending_protocol_version = @protocol_version
        end

        if transition_id.zero?
          execute_transition(transition_id)
        else
          transition_ready(transition_id)
        end
      end

      # Executes the transition that was prepared earlier. Every other transition is ignored, because there is
      # nothing this connection could switch to.
      def execute_transition(transition_id)
        if @pending_transition_id != transition_id
          DAVE.logger.warn("Ignoring DAVE transition #{transition_id} because it was not prepared")
          return
        end

        protocol_version = @pending_protocol_version
        @pending_transition_id = nil
        @pending_protocol_version = nil
        @protocol_version = protocol_version
        apply_transition(protocol_version)
      end

      # Switches the outgoing audio to the key ratchet of the new epoch, or to passthrough mode for version 0.
      def apply_transition(protocol_version)
        target = encryptor
        return if target.nil?

        if protocol_version.zero?
          target.passthrough = true
          @key_ratchet&.destroy
          @key_ratchet = nil
          @encryption_established = false
          @dropping_frames = false
          return
        end

        ratchet = @session&.key_ratchet(@self_user_id)
        if ratchet.nil?
          # The group is not established yet. A connection that has already encrypted media must not fall back to
          # plaintext frames, so it drops them until the new group provides a key.
          @dropping_frames = @encryption_established
          return
        end

        @key_ratchet&.destroy
        @key_ratchet = ratchet
        target.key_ratchet = ratchet
        target.passthrough = false
        @encryption_established = true
        @dropping_frames = false
      end

      def transition_ready(transition_id)
        @send_json.call(Opcodes::DAVE_TRANSITION_READY, { transition_id: transition_id })
      end

      # Tells the gateway that a commit or welcome could not be processed and starts over with a new group, which is
      # how the DAVE protocol recovers from a broken MLS state.
      def invalid_transition(transition_id)
        DAVE.logger.warn("Rejecting DAVE transition #{transition_id} and resetting the MLS group")
        @send_json.call(Opcodes::DAVE_MLS_INVALID_COMMIT_WELCOME, { transition_id: transition_id })

        @pending_transition_id = nil
        @pending_protocol_version = nil
        reset_group(@protocol_version) if @protocol_version.positive?
      end
    end
  end
end
