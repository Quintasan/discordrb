# frozen_string_literal: true

require 'ffi'
require 'discordrb/logger'

# Voice support
module Discordrb::Voice
  # Discord's Audio & Video End-to-End Encryption (DAVE) protocol.
  #
  # The protocol itself (an MLS group for the key exchange, AES-128-GCM for the media frames) is implemented by
  # libdave, Discord's own implementation, which is used through its C API. libdave is not shipped with discordrb;
  # see {available?} for how to provide it.
  #
  # When libdave is not available, voice connections still work, but they do not declare DAVE support and therefore
  # cannot take part in end-to-end encrypted calls.
  module DAVE
    # The highest DAVE protocol version discordrb implements.
    MAX_PROTOCOL_VERSION = 1

    # Size of the sequence number that prefixes every binary message sent by the voice gateway.
    # @!visibility private
    SEQUENCE_NUMBER_SIZE = 2

    # Parsing and building of the binary voice gateway messages that carry the DAVE handshake.
    #
    # Messages from the gateway are prefixed with a big-endian sequence number, messages to the gateway are not.
    # @!visibility private
    module Framing
      module_function

      # Splits a binary message from the voice gateway into its parts.
      # @param data [String] the raw websocket message
      # @return [Array(Integer, Integer, String)] the sequence number, the opcode and the payload
      def parse_server_message(data)
        data = data.to_s.b
        raise ArgumentError, 'binary voice message is shorter than its header' if data.bytesize < SEQUENCE_NUMBER_SIZE + 1

        [data.unpack1('n'), data.getbyte(SEQUENCE_NUMBER_SIZE), data.byteslice((SEQUENCE_NUMBER_SIZE + 1)..) || ''.b]
      end

      # Splits the transition ID off a payload that starts with one.
      # @param payload [String]
      # @return [Array(Integer, String)] the transition ID and the rest of the payload
      def split_transition(payload)
        payload = payload.to_s.b
        raise ArgumentError, 'DAVE message is shorter than its transition ID' if payload.bytesize < 2

        [payload.unpack1('n'), payload.byteslice(2..) || ''.b]
      end

      # Builds a binary message for the voice gateway.
      # @param opcode [Integer]
      # @param payload [String]
      # @return [String]
      def client_message(opcode, payload)
        ([opcode].pack('C') + payload.to_s.b).b
      end
    end

    class << self
      # Whether libdave could be loaded. The library is looked up as `DAVE_LIBRARY_PATH` if that environment variable
      # is set, and by its usual name (`libdave.so`, `libdave.dylib`, `dave.dll`) otherwise. Prebuilt binaries can be
      # downloaded from https://github.com/discord/libdave/releases.
      # @return [Boolean]
      def available?
        return @available unless @available.nil?

        @available = load_library
      end

      # Forgets whether libdave could be loaded, so that the next {available?} call looks for it again. This is
      # useful for tests, and for scripts that install libdave while the bot is running.
      # @return [void]
      def reset_availability!
        @available = nil
      end

      # The DAVE protocol version that voice connections should declare. Zero means that the connection does not
      # support DAVE, which is the case when libdave is unavailable.
      # @return [Integer]
      def supported_protocol_version
        return 0 unless available?

        [Library.daveMaxSupportedProtocolVersion, MAX_PROTOCOL_VERSION].min
      end

      # The logger used for the DAVE code, which falls back to a new logger when discordrb's global logger is not
      # defined yet.
      # @return [Discordrb::Logger]
      def logger
        return Discordrb::LOGGER if defined?(Discordrb::LOGGER)

        @logger ||= Discordrb::Logger.new
      end

      private

      def load_library
        require_relative 'dave/library'
        install_log_sink
        logger.debug("Loaded libdave from #{Library.loaded_path || 'the dynamic linker search path'}")
        true
      rescue LoadError, FFI::NotFoundError => e
        logger.warn('libdave could not be loaded, so voice connections will not use DAVE end-to-end ' \
                    "encryption: #{e.message}")
        false
      end

      # Routes libdave's log output through discordrb's logger instead of stdout.
      def install_log_sink
        @log_sink = FFI::Function.new(:void, %i[int string int string]) do |severity, file, line, message|
          location = "#{::File.basename(file)}:#{line}"
          case severity
          when Library::SEVERITY_VERBOSE, Library::SEVERITY_INFO
            logger.debug("libdave: #{message} (#{location})")
          when Library::SEVERITY_WARNING
            logger.warn("libdave: #{message} (#{location})")
          else
            logger.error("libdave: #{message} (#{location})")
          end
        end

        Library.daveSetLogSinkCallback(@log_sink)
      end
    end
  end
end

# The wrappers only call into libdave when they are used, so they can be loaded whether or not the library exists.
require_relative 'dave/session'
