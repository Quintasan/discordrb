# frozen_string_literal: true

require_relative '../dave'

module Discordrb::Voice
  module DAVE
    # Wraps a libdave MLS session: the group state, the key packages and the commits of a single voice connection.
    # @!visibility private
    class Session
      # @param self_user_id [String, Integer] the ID of the user this session belongs to
      def initialize(self_user_id)
        @self_user_id = self_user_id.to_s
        @handle = Library.daveSessionCreate(nil, nil, nil, nil)
        raise 'libdave could not create a DAVE session' if @handle.null?
      end

      # Creates (or resets) the local group state for the given protocol version.
      # @param protocol_version [Integer] the DAVE protocol version of the group
      # @param group_id [Integer] the identifier shared by all members of the group, the voice channel's ID
      def init(protocol_version, group_id)
        Library.daveSessionInit(@handle, protocol_version, group_id, @self_user_id)
      end

      # @param version [Integer] the new DAVE protocol version
      def protocol_version=(version)
        Library.daveSessionSetProtocolVersion(@handle, version)
      end

      # @return [Integer] the DAVE protocol version of the current group
      def protocol_version
        Library.daveSessionGetProtocolVersion(@handle)
      end

      # Sets the voice gateway as the external sender of the group. Must be called before the group is created.
      # @param package [String] the serialized external sender package from voice opcode 25
      def external_sender=(package)
        bytes = package.to_s.b
        pointer = FFI::MemoryPointer.from_string(bytes)
        Library.daveSessionSetExternalSender(@handle, pointer, bytes.bytesize)
      end

      # Marks a user as being connected to the call, so their add proposal can be processed.
      # @param user_id [String, Integer]
      def add_recognized_user(user_id)
        Library.daveSessionAddRecognizedUser(@handle, user_id.to_s)
      end

      # Marks a user as no longer being connected to the call.
      # @param user_id [String, Integer]
      def remove_recognized_user(user_id)
        Library.daveSessionRemoveRecognizedUser(@handle, user_id.to_s)
      end

      # @return [String, nil] the serialized MLS key package to send with voice opcode 26
      def marshalled_key_package
        read_output_buffer { |pointer, length| Library.daveSessionGetMarshalledKeyPackage(@handle, pointer, length) }
      end

      # Appends or revokes the MLS proposals from voice opcode 27 and produces a commit for them.
      # @param proposals [String] the payload of voice opcode 27, without its opcode and sequence number
      # @return [String, nil] the serialized commit and welcome to send with voice opcode 28, if a commit is needed
      def process_proposals(proposals)
        bytes = proposals.to_s.b
        pointer = FFI::MemoryPointer.from_string(bytes)
        read_output_buffer do |out_pointer, out_length|
          Library.daveSessionProcessProposals(@handle, pointer, bytes.bytesize, out_pointer, out_length)
        end
      end

      # Applies a commit broadcast by the voice gateway.
      # @param commit [String] the serialized MLS commit, without the transition ID
      # @return [CommitResult, nil] the result of applying the commit, or `nil` if it could not be processed
      def process_commit(commit)
        with_input_buffer(commit) do |pointer, length|
          handle = Library.daveSessionProcessCommit(@handle, pointer, length)
          handle.null? ? nil : CommitResult.new(handle)
        end
      end

      # Applies a welcome broadcast by the voice gateway, joining the group it describes.
      # @param welcome [String] the serialized MLS welcome, without the transition ID
      # @return [Boolean] whether the welcome could be processed
      def process_welcome(welcome)
        with_input_buffer(welcome) do |pointer, length|
          handle = Library.daveSessionProcessWelcome(@handle, pointer, length)
          next false if handle.null?

          Library.daveWelcomeResultDestroy(handle)
          true
        end
      end

      # Derives the media key ratchet of a group member for the current epoch.
      # @param user_id [String, Integer] the member to derive the ratchet for
      # @return [KeyRatchet, nil] the ratchet, or `nil` if the group is not established or the user is not a member
      def key_ratchet(user_id)
        handle = Library.daveSessionGetKeyRatchet(@handle, user_id.to_s)
        handle.null? ? nil : KeyRatchet.new(handle)
      end

      def destroy
        return if @handle.null?

        Library.daveSessionDestroy(@handle)
        @handle = FFI::Pointer::NULL
      end

      private

      def read_output_buffer
        out_pointer = FFI::MemoryPointer.new(:pointer)
        out_length = FFI::MemoryPointer.new(:size_t)
        yield(out_pointer, out_length)

        pointer = out_pointer.read_pointer
        return nil if pointer.null?

        data = pointer.read_bytes(out_length.read(:size_t)).b
        Library.daveFree(pointer)
        data
      end

      def with_input_buffer(bytes)
        data = bytes.to_s.b
        return yield(FFI::Pointer::NULL, 0) if data.empty?

        yield(FFI::MemoryPointer.from_string(data), data.bytesize)
      end
    end

    # The result of applying an MLS commit to a {Session}.
    # @!visibility private
    class CommitResult
      def initialize(handle)
        @handle = handle
      end

      # @return [Boolean] whether the commit could not be applied
      def failed?
        Library.daveCommitResultIsFailed(@handle)
      end

      # @return [Boolean] whether the commit does not change the local group state
      def ignored?
        Library.daveCommitResultIsIgnored(@handle)
      end

      def destroy
        return if @handle.null?

        Library.daveCommitResultDestroy(@handle)
        @handle = FFI::Pointer::NULL
      end
    end

    # A media key ratchet for one sender, as derived from an established MLS group.
    # @!visibility private
    class KeyRatchet
      def initialize(handle)
        @handle = handle
      end

      # @return [FFI::Pointer] the underlying handle, which libdave does not take ownership of
      def to_ptr
        @handle
      end

      def destroy
        return if @handle.null?

        Library.daveKeyRatchetDestroy(@handle)
        @handle = FFI::Pointer::NULL
      end
    end

    # Encrypts outgoing media frames with the DAVE protocol, or passes them through unencrypted.
    # @!visibility private
    class Encryptor
      # @param ssrc [Integer] the SSRC of this connection
      # @param codec [Integer] the codec used for that SSRC, see {Library::CODEC_OPUS}
      def initialize(ssrc, codec: Library::CODEC_OPUS)
        @handle = Library.daveEncryptorCreate
        raise 'libdave could not create a DAVE encryptor' if @handle.null?

        @key_ratchet = nil
        @codec = codec
        @passthrough = true
        Library.daveEncryptorSetPassthroughMode(@handle, true)
        Library.daveEncryptorAssignSsrcToCodec(@handle, ssrc, codec) if ssrc
      end

      # @param value [Integer, nil] the SSRC of this connection
      def ssrc=(value)
        Library.daveEncryptorAssignSsrcToCodec(@handle, value, @codec) if value
      end

      # @return [Boolean] whether frames are passed through unencrypted
      def passthrough?
        Library.daveEncryptorIsPassthroughMode(@handle)
      end

      # @param value [Boolean] whether frames should be passed through unencrypted
      def passthrough=(value)
        Library.daveEncryptorSetPassthroughMode(@handle, value)
      end

      # @param ratchet [KeyRatchet] the ratchet for this connection's own user
      def key_ratchet=(ratchet)
        Library.daveEncryptorSetKeyRatchet(@handle, ratchet.to_ptr)
        @key_ratchet = ratchet
      end

      # Encrypts an audio frame.
      # @param frame [String] one Opus frame
      # @param ssrc [Integer] the SSRC that the frame is sent with
      # @return [String, nil] the encrypted frame, or `nil` if it could not be encrypted
      def encrypt(frame, ssrc)
        bytes = frame.to_s.b
        capacity = Library.daveEncryptorGetMaxCiphertextByteSize(@handle, Library::MEDIA_TYPE_AUDIO, bytes.bytesize)
        out = FFI::MemoryPointer.new(:uint8, capacity)
        written = FFI::MemoryPointer.new(:size_t)
        result = Library.daveEncryptorEncrypt(@handle, Library::MEDIA_TYPE_AUDIO, ssrc,
                                              FFI::MemoryPointer.from_string(bytes), bytes.bytesize, out, capacity,
                                              written)

        if result != Library::ENCRYPTOR_SUCCESS
          DAVE.logger.warn("DAVE frame encryption failed with result code #{result}")
          return nil
        end

        out.read_bytes(written.read(:size_t))
      end

      def destroy
        @key_ratchet = nil
        return if @handle.null?

        Library.daveEncryptorDestroy(@handle)
        @handle = FFI::Pointer::NULL
      end
    end
  end
end
