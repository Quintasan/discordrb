# frozen_string_literal: true

require 'discordrb/voice/dave'
require 'discordrb/voice/dave/handler'

describe Discordrb::Voice::DAVE do
  describe '.supported_protocol_version' do
    it 'is 0 when libdave is not available' do
      allow(described_class).to receive(:available?).and_return(false)
      expect(described_class.supported_protocol_version).to eq 0
    end

    it 'is capped at the version discordrb implements' do
      stub_const('Discordrb::Voice::DAVE::Library', double(daveMaxSupportedProtocolVersion: described_class::MAX_PROTOCOL_VERSION + 5))
      allow(described_class).to receive(:available?).and_return(true)
      expect(described_class.supported_protocol_version).to eq described_class::MAX_PROTOCOL_VERSION
    end

    it 'follows libdave when it supports less than discordrb does' do
      stub_const('Discordrb::Voice::DAVE::Library', double(daveMaxSupportedProtocolVersion: 0))
      allow(described_class).to receive(:available?).and_return(true)
      expect(described_class.supported_protocol_version).to eq 0
    end
  end

  describe '.available?' do
    after { described_class.reset_availability! }

    it 'looks for libdave again after the result was forgotten' do
      allow(described_class).to receive(:load_library).and_return(false, true)
      described_class.reset_availability!
      expect(described_class.available?).to be false

      described_class.reset_availability!

      expect(described_class.available?).to be true
    end
  end

  describe Discordrb::Voice::DAVE::Framing do
    describe '.parse_server_message' do
      it 'splits the sequence number, the opcode and the payload' do
        message = [7, 27].pack('nC') + "\x01\x02\x03".b
        expect(described_class.parse_server_message(message)).to eq [7, 27, "\x01\x02\x03".b]
      end

      it 'accepts a message without a payload' do
        expect(described_class.parse_server_message([1, 29].pack('nC'))).to eq [1, 29, ''.b]
      end

      it 'raises on a message that is too short' do
        expect { described_class.parse_server_message("\x00\x01") }.to raise_error(ArgumentError)
      end
    end

    describe '.split_transition' do
      it 'splits the transition ID off the payload' do
        expect(described_class.split_transition("#{[3].pack('n')}commit")).to eq [3, 'commit']
      end

      it 'raises when the transition ID is missing' do
        expect { described_class.split_transition("\x01") }.to raise_error(ArgumentError)
      end
    end

    describe '.client_message' do
      it 'prefixes the payload with the opcode' do
        expect(described_class.client_message(26, 'package')).to eq "\x1Apackage".b
      end
    end
  end
end

describe Discordrb::Voice::DAVE::Handler do
  subject(:handler) do
    described_class.new(
      channel_id: channel_id,
      self_user_id: self_user_id,
      send_json: ->(opcode, data) { sent << [opcode, data] },
      send_binary: ->(opcode, payload) { sent << [opcode, payload] },
      session_factory: -> { session }
    )
  end

  let(:channel_id) { 456 }
  let(:self_user_id) { 123 }
  let(:sent) { [] }
  let(:opcodes) { Discordrb::Voice::Opcodes }
  let(:session) { instance_double(Discordrb::Voice::DAVE::Session) }

  before do
    allow(session).to receive(:init)
    allow(session).to receive(:destroy)
    allow(session).to receive(:add_recognized_user)
    allow(session).to receive(:remove_recognized_user)
    allow(session).to receive(:external_sender=)
    allow(session).to receive(:protocol_version=)
    allow(session).to receive(:marshalled_key_package).and_return('key-package')
    allow(session).to receive(:process_proposals)
  end

  # The gateway only sends handshake messages once the client has a local group, so most tests need an epoch first.
  def start_group(protocol_version = 1)
    handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => protocol_version, 'epoch' => 1 })
    sent.clear
  end

  it 'starts with protocol version 0 and no messages sent' do
    expect(handler.protocol_version).to eq 0
    expect(sent).to be_empty
  end

  describe 'the initial epoch' do
    it 'creates a group and sends a key package' do
      handler.handle_binary(opcodes::DAVE_MLS_EXTERNAL_SENDER, 'external-sender')
      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 1 })

      expect(session).to have_received(:init).with(1, channel_id)
      expect(sent).to eq [[opcodes::DAVE_MLS_KEY_PACKAGE, 'key-package']]
    end

    it 'keeps the external sender when it arrived before the epoch' do
      handler.handle_binary(opcodes::DAVE_MLS_EXTERNAL_SENDER, 'external-sender')
      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 1 })

      expect(session).to have_received(:external_sender=).with('external-sender')
    end

    it 'sets the external sender on an existing session' do
      handler.handle_json(opcodes::SESSION_DESCRIPTION, { 'dave_protocol_version' => 1 })
      handler.handle_binary(opcodes::DAVE_MLS_EXTERNAL_SENDER, 'external-sender')

      expect(session).to have_received(:external_sender=).with('external-sender')
      expect(sent).to eq [[opcodes::DAVE_MLS_KEY_PACKAGE, 'key-package']]
    end

    it 're-adds the users that are connected to the call' do
      handler.handle_json(opcodes::CLIENT_CONNECT, { 'user_ids' => %w[123 456] })
      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 1 })

      expect(session).to have_received(:add_recognized_user).with('123').at_least(:once)
      expect(session).to have_received(:add_recognized_user).with('456').at_least(:once)
    end

    it 'only changes the protocol version for a later epoch' do
      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 1 })
      sent.clear
      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 2 })

      expect(session).to have_received(:protocol_version=).with(1)
      expect(sent).to be_empty
    end
  end

  describe 'the protocol version' do
    it 'prepares a group and a key package once the gateway picks version 1' do
      handler.handle_json(opcodes::SESSION_DESCRIPTION, { 'dave_protocol_version' => 1 })

      expect(handler.protocol_version).to eq 1
      expect(session).to have_received(:init).with(1, channel_id)
      expect(sent).to be_empty
    end

    it 'does not send a key package before the gateway picks a version' do
      handler.handle_binary(opcodes::DAVE_MLS_EXTERNAL_SENDER, 'external-sender')

      expect(sent).to be_empty
    end

    it 'does nothing when the gateway picks version 0' do
      handler.handle_json(opcodes::SESSION_DESCRIPTION, { 'dave_protocol_version' => 0 })

      expect(handler.protocol_version).to eq 0
      expect(session).not_to have_received(:init)
      expect(sent).to be_empty
    end
  end

  describe 'recognized users' do
    it 'marks connected users as recognized' do
      start_group
      handler.handle_json(opcodes::CLIENT_CONNECT, { 'user_ids' => ['789'] })

      expect(session).to have_received(:add_recognized_user).with('789')
    end

    it 'unmarks disconnected users' do
      start_group
      handler.handle_json(opcodes::CLIENT_CONNECT, { 'user_ids' => ['789'] })
      handler.handle_json(opcodes::CLIENT_DISCONNECT, { 'user_id' => '789' })

      expect(session).to have_received(:remove_recognized_user).with('789')
    end
  end

  describe 'proposals' do
    it 'answers the proposals of the gateway with a commit' do
      start_group
      allow(session).to receive(:process_proposals).with("\x00proposal").and_return('commit-welcome')

      handler.handle_binary(opcodes::DAVE_MLS_PROPOSALS, "\x00proposal".b)

      expect(sent).to eq [[opcodes::DAVE_MLS_COMMIT_WELCOME, 'commit-welcome']]
    end

    it 'sends nothing when no commit is needed' do
      start_group
      allow(session).to receive(:process_proposals).and_return(nil)

      handler.handle_binary(opcodes::DAVE_MLS_PROPOSALS, "\x00proposal".b)

      expect(sent).to be_empty
    end
  end

  describe 'commits' do
    let(:commit_result) { instance_double(Discordrb::Voice::DAVE::CommitResult, failed?: false, ignored?: false) }

    before { allow(commit_result).to receive(:destroy) }

    it 'reports that it is ready for the transition' do
      start_group
      allow(session).to receive(:process_commit).with('commit').and_return(commit_result)

      handler.handle_binary(opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION, "#{[9].pack('n')}commit")

      expect(sent).to eq [[opcodes::DAVE_TRANSITION_READY, { transition_id: 9 }]]
    end

    it 'rejects a commit it cannot process and starts over with a new group' do
      handler.handle_binary(opcodes::DAVE_MLS_EXTERNAL_SENDER, 'external-sender')
      start_group
      allow(commit_result).to receive(:failed?).and_return(true)
      allow(session).to receive(:process_commit).and_return(commit_result)

      handler.handle_binary(opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION, "#{[9].pack('n')}commit")

      expect(sent).to eq [
        [opcodes::DAVE_MLS_INVALID_COMMIT_WELCOME, { transition_id: 9 }],
        [opcodes::DAVE_MLS_KEY_PACKAGE, 'key-package']
      ]
      expect(session).to have_received(:init).with(1, channel_id).twice
    end

    it 'stays quiet about its own commit' do
      start_group
      allow(commit_result).to receive(:ignored?).and_return(true)
      allow(session).to receive(:process_commit).and_return(commit_result)

      handler.handle_binary(opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION, "#{[9].pack('n')}commit")

      expect(sent).to be_empty
    end

    it 'ignores a commit message that is too short to carry a transition ID' do
      start_group
      allow(session).to receive(:process_commit)

      handler.handle_binary(opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION, "\x09".b)

      expect(sent).to be_empty
      expect(session).not_to have_received(:process_commit)
    end

    it 'executes the initial transition right away instead of answering it' do
      ratchet = instance_double(Discordrb::Voice::DAVE::KeyRatchet)
      allow(ratchet).to receive(:destroy)
      allow(session).to receive(:key_ratchet).with(self_user_id.to_s).and_return(ratchet)
      allow(session).to receive(:process_commit).with('commit').and_return(commit_result)

      encryptor = instance_double(Discordrb::Voice::DAVE::Encryptor, passthrough?: true)
      allow(encryptor).to receive(:destroy)
      allow(encryptor).to receive(:passthrough=)
      allow(encryptor).to receive(:key_ratchet=)
      allow(Discordrb::Voice::DAVE::Encryptor).to receive(:new).and_return(encryptor)
      handler.ssrc = 9001

      start_group
      handler.handle_binary(opcodes::DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION, "#{[0].pack('n')}commit")

      expect(sent).to be_empty
      expect(encryptor).to have_received(:key_ratchet=).with(ratchet)
      expect(encryptor).to have_received(:passthrough=).with(false)
    end
  end

  describe 'welcomes' do
    it 'reports that it is ready for the transition' do
      start_group
      allow(session).to receive(:process_welcome).with('welcome').and_return(true)

      handler.handle_binary(opcodes::DAVE_MLS_WELCOME, "#{[4].pack('n')}welcome")

      expect(sent).to eq [[opcodes::DAVE_TRANSITION_READY, { transition_id: 4 }]]
    end

    it 'executes the initial transition right away instead of answering it' do
      start_group
      allow(session).to receive(:process_welcome).with('welcome').and_return(true)

      handler.handle_binary(opcodes::DAVE_MLS_WELCOME, "#{[0].pack('n')}welcome")

      expect(sent).to be_empty
    end

    it 'rejects a welcome it cannot process and resets the group' do
      start_group
      allow(session).to receive(:process_welcome).and_return(false)

      handler.handle_binary(opcodes::DAVE_MLS_WELCOME, "#{[4].pack('n')}welcome")

      expect(sent).to eq [[opcodes::DAVE_MLS_INVALID_COMMIT_WELCOME, { transition_id: 4 }]]
      expect(session).to have_received(:init).with(1, channel_id).twice
    end
  end

  describe 'transitions' do
    it 'executes a transition with ID 0 without answering' do
      handler.handle_json(opcodes::DAVE_PREPARE_TRANSITION, { 'protocol_version' => 1, 'transition_id' => 0 })

      expect(sent).to be_empty
    end

    it 'answers other transitions with ready' do
      handler.handle_json(opcodes::DAVE_PREPARE_TRANSITION, { 'protocol_version' => 1, 'transition_id' => 5 })

      expect(sent).to eq [[opcodes::DAVE_TRANSITION_READY, { transition_id: 5 }]]
    end

    it 'starts encrypting after the transition is executed' do
      ratchet = instance_double(Discordrb::Voice::DAVE::KeyRatchet)
      allow(ratchet).to receive(:destroy)
      allow(session).to receive(:key_ratchet).with(self_user_id.to_s).and_return(ratchet)

      encryptor = instance_double(Discordrb::Voice::DAVE::Encryptor, passthrough?: true)
      allow(encryptor).to receive(:destroy)
      allow(encryptor).to receive(:passthrough=)
      allow(encryptor).to receive(:key_ratchet=)
      allow(Discordrb::Voice::DAVE::Encryptor).to receive(:new).and_return(encryptor)
      handler.ssrc = 9001

      start_group
      handler.handle_json(opcodes::SESSION_DESCRIPTION, { 'dave_protocol_version' => 1 })
      handler.handle_json(opcodes::DAVE_PREPARE_TRANSITION, { 'protocol_version' => 1, 'transition_id' => 5 })
      handler.handle_json(opcodes::DAVE_EXECUTE_TRANSITION, { 'transition_id' => 5 })

      expect(encryptor).to have_received(:key_ratchet=).with(ratchet)
      expect(encryptor).to have_received(:passthrough=).with(false)
    end

    it 'ignores an execute for a transition that was never prepared' do
      ratchet = instance_double(Discordrb::Voice::DAVE::KeyRatchet)
      allow(ratchet).to receive(:destroy)
      allow(session).to receive(:key_ratchet).with(self_user_id.to_s).and_return(ratchet)

      encryptor = instance_double(Discordrb::Voice::DAVE::Encryptor, passthrough?: true)
      allow(encryptor).to receive(:destroy)
      allow(encryptor).to receive(:passthrough=)
      allow(encryptor).to receive(:key_ratchet=)
      allow(Discordrb::Voice::DAVE::Encryptor).to receive(:new).and_return(encryptor)
      handler.ssrc = 9001

      start_group
      handler.handle_json(opcodes::SESSION_DESCRIPTION, { 'dave_protocol_version' => 1 })
      handler.handle_json(opcodes::DAVE_EXECUTE_TRANSITION, { 'transition_id' => 7 })

      expect(encryptor).not_to have_received(:key_ratchet=)
      expect(encryptor).not_to have_received(:passthrough=)
    end
  end

  describe '#encrypt_audio' do
    let(:encryptor) { instance_double(Discordrb::Voice::DAVE::Encryptor) }

    before do
      allow(encryptor).to receive(:destroy)
      allow(Discordrb::Voice::DAVE::Encryptor).to receive(:new).and_return(encryptor)
      handler.ssrc = 9001
    end

    it 'passes frames through while no group is established' do
      allow(encryptor).to receive(:passthrough?).and_return(true)

      expect(handler.encrypt_audio('frame')).to eq 'frame'
    end

    it 'encrypts frames for an established group' do
      allow(encryptor).to receive(:passthrough?).and_return(false)
      allow(encryptor).to receive(:encrypt).with('frame', 9001).and_return('encrypted')

      expect(handler.encrypt_audio('frame')).to eq 'encrypted'
    end

    it 'drops frames that cannot be encrypted' do
      allow(encryptor).to receive(:passthrough?).and_return(false)
      allow(encryptor).to receive(:encrypt).and_return(nil)

      expect(handler.encrypt_audio('frame')).to be_nil
    end

    it 'still passes frames through after a reset as long as nothing was encrypted yet' do
      allow(encryptor).to receive(:passthrough?).and_return(true)

      start_group
      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 1 })

      expect(handler.encrypt_audio('frame')).to eq 'frame'
    end

    it 'drops frames after a reset instead of sending them unencrypted' do
      ratchet = instance_double(Discordrb::Voice::DAVE::KeyRatchet)
      allow(ratchet).to receive(:destroy)
      allow(session).to receive(:key_ratchet).with(self_user_id.to_s).and_return(ratchet)
      allow(encryptor).to receive(:passthrough?).and_return(false)
      allow(encryptor).to receive(:passthrough=)
      allow(encryptor).to receive(:key_ratchet=)
      allow(encryptor).to receive(:encrypt).and_return('encrypted')

      start_group
      handler.handle_json(opcodes::SESSION_DESCRIPTION, { 'dave_protocol_version' => 1 })
      handler.handle_json(opcodes::DAVE_PREPARE_TRANSITION, { 'protocol_version' => 1, 'transition_id' => 0 })
      expect(handler.encrypt_audio('frame')).to eq 'encrypted'

      handler.handle_json(opcodes::DAVE_PREPARE_EPOCH, { 'protocol_version' => 1, 'epoch' => 1 })

      expect(handler.encrypt_audio('frame')).to be_nil
    end
  end

  describe '#close' do
    it 'destroys the session and ignores later messages' do
      start_group
      handler.close
      handler.handle_binary(opcodes::DAVE_MLS_PROPOSALS, 'proposal')

      expect(session).to have_received(:destroy)
      expect(session).not_to have_received(:process_proposals)
    end
  end
end

describe Discordrb::Voice::DAVE::Session do
  it 'creates a key package with the real libdave' do
    skip 'libdave is not installed' unless Discordrb::Voice::DAVE.available?

    session = described_class.new(123)
    begin
      session.init(1, 456)
      key_package = session.marshalled_key_package

      expect(key_package.bytesize).to be > 100
      expect(key_package.byteslice(0, 2)).to eq "\x00\x01".b
      expect(session.key_ratchet(123)).to be_nil
    ensure
      session.destroy
    end
  end
end
