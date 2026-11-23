# frozen_string_literal: true

require 'ffi'

module Discordrb::Voice
  module DAVE
    # FFI bindings for Discord's libdave C API.
    #
    # libdave is not distributed with a system package manager, so it has to be built or downloaded from
    # https://github.com/discord/libdave/releases. Set `DAVE_LIBRARY_PATH` to the full path of the shared library if
    # it is not in the dynamic linker's search path.
    #
    # @!visibility private
    module Library
      extend FFI::Library

      LIBRARY_NAMES = %w[libdave.so libdave.so.1 libdave.dylib libdave.dylib.1 dave.dll libdave.dll].freeze

      MEDIA_TYPE_AUDIO = 0
      MEDIA_TYPE_VIDEO = 1

      CODEC_OPUS = 1

      ENCRYPTOR_SUCCESS = 0

      SEVERITY_VERBOSE = 0
      SEVERITY_INFO = 1
      SEVERITY_WARNING = 2
      SEVERITY_ERROR = 3

      class << self
        # @return [String, nil] the path that libdave is loaded from, if it was loaded from an explicit path.
        attr_reader :loaded_path

        # Sets the path libdave is loaded from. Called before the bindings are attached.
        def library_candidates
          configured = ENV.fetch('DAVE_LIBRARY_PATH', nil)
          return [configured] if configured && !configured.empty?

          LIBRARY_NAMES
        end
      end

      ffi_lib library_candidates
      @loaded_path = ENV.fetch('DAVE_LIBRARY_PATH', nil)

      # Callbacks. These have to stay referenced for as long as libdave may call them.
      callback :mls_failure_callback, %i[string string pointer], :void
      callback :log_sink_callback, %i[int string int string], :void

      attach_function :daveMaxSupportedProtocolVersion, [], :uint16
      attach_function :daveFree, [:pointer], :void
      attach_function :daveSetLogSinkCallback, [:log_sink_callback], :void

      attach_function :daveSessionCreate, %i[pointer string mls_failure_callback pointer], :pointer
      attach_function :daveSessionDestroy, [:pointer], :void
      attach_function :daveSessionInit, %i[pointer uint16 uint64 string], :void
      attach_function :daveSessionSetProtocolVersion, %i[pointer uint16], :void
      attach_function :daveSessionGetProtocolVersion, [:pointer], :uint16
      attach_function :daveSessionSetExternalSender, %i[pointer pointer size_t], :void
      attach_function :daveSessionAddRecognizedUser, %i[pointer string], :void
      attach_function :daveSessionRemoveRecognizedUser, %i[pointer string], :void
      attach_function :daveSessionGetMarshalledKeyPackage, %i[pointer pointer pointer], :void
      attach_function :daveSessionGetKeyRatchet, %i[pointer string], :pointer
      attach_function :daveSessionProcessProposals, %i[pointer pointer size_t pointer pointer], :void
      attach_function :daveSessionProcessCommit, %i[pointer pointer size_t], :pointer
      attach_function :daveSessionProcessWelcome, %i[pointer pointer size_t], :pointer
      attach_function :daveCommitResultIsFailed, [:pointer], :bool
      attach_function :daveCommitResultIsIgnored, [:pointer], :bool
      attach_function :daveCommitResultGetRosterMemberIds, %i[pointer pointer pointer], :void
      attach_function :daveCommitResultDestroy, [:pointer], :void

      attach_function :daveWelcomeResultDestroy, [:pointer], :void
      attach_function :daveKeyRatchetDestroy, [:pointer], :void
      attach_function :daveEncryptorCreate, [], :pointer
      attach_function :daveEncryptorDestroy, [:pointer], :void
      attach_function :daveEncryptorSetKeyRatchet, %i[pointer pointer], :void
      attach_function :daveEncryptorSetPassthroughMode, %i[pointer bool], :void
      attach_function :daveEncryptorIsPassthroughMode, [:pointer], :bool
      attach_function :daveEncryptorAssignSsrcToCodec, %i[pointer uint32 int], :void
      attach_function :daveEncryptorGetMaxCiphertextByteSize, %i[pointer int size_t], :size_t
      attach_function :daveEncryptorEncrypt, %i[pointer int uint32 pointer size_t pointer size_t pointer], :int
    end
  end
end
