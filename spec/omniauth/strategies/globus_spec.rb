# frozen_string_literal: true

require 'spec_helper'

describe OmniAuth::Strategies::Globus do
  let(:request) { double('Request', :params => {}, :cookies => {}, :env => {}) }
  let(:app) {
    lambda do
      [200, {}, ["Hello."]]
    end
  }

  subject do
    OmniAuth::Strategies::Globus.new(app, 'client_id', 'client_secret', @options || {}).tap do |strategy|
      allow(strategy).to receive(:request) {
        request
      }
    end
  end

  before do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  context 'options' do
    it 'should have correct name' do
      expect(subject.options.name).to eq('globus')
    end

    it 'should have correct issuer' do
      expect(subject.options.issuer).to eq('https://auth.globus.org')
    end

    it 'should have correct scope' do
      expect(subject.options.scope).to eq("openid profile email")
    end
  end

  context 'client options' do
    it 'should have correct discovery_endpoint' do
      expect(subject.options.client_options.discovery_endpoint).to eq("https://auth.globus.org/.well-known/openid-configuration")
    end


    it 'should have correct authorization_endpoint' do
      expect(subject.options.client_options.authorization_endpoint).to eq("https://auth.globus.org/v2/oauth2/authorize")
    end

    it 'should have correct token_endpoint' do
      expect(subject.options.client_options.token_endpoint).to eq("https://auth.globus.org/v2/oauth2/token")
    end

    it 'should have correct userinfo_endpoint' do
      expect(subject.options.client_options.userinfo_endpoint).to eq("https://auth.globus.org/v2/oauth2/userinfo")
    end

    it 'should have correct end_session_endpoint' do
      expect(subject.options.client_options.end_session_endpoint).to eq("https://auth.globus.org/v2/oauth2/token/revoke")
    end
  end

    # describe "redirect_uri" do
    #   it 'should default to nil' do
    #     @options = {}
    #     expect(subject.authorize_params['redirect_uri']).to be_nil
    #   end

    #   it 'should set the redirect_uri parameter if present' do
    #     @options = { redirect_uri: 'https://example.com' }
    #     expect(subject.authorize_params['redirect_uri']).to eq('https://example.com')
    #   end
    # end

    # describe "scope" do
    #   it 'should default to nil' do
    #     @options = {}
    #     expect(subject.authorize_params['scope']).to eq("/authenticate")
    #   end

    #   it 'should set the scope parameter if present' do
    #     @options = { scope: '/read-limited' }
    #     expect(subject.authorize_params['scope']).to eq("/read-limited")
    #   end
    # end

  describe 'info' do
    let(:client) do
      OAuth2::Client.new('abc', 'def') do |builder|
        builder.request :url_encoded
        builder.adapter :test do |stub|
          stub.get('/oauth2/v3/userinfo') { [200, { 'content-type' => 'application/json' }, response_hash.to_json] }
        end
      end
    end
    let(:access_token) { OAuth2::AccessToken.from_hash(client, {}) }
    before { allow(subject).to receive(:access_token).and_return(access_token) }

    context 'with email' do
      let(:response_hash) do
        { email: 'something@domain.invalid' }
      end

      it 'should return email' do
        expect(subject.info[:email]).to eq('something@domain.invalid')
      end
    end
  end

  describe '#extra' do
    let(:client) do
      OAuth2::Client.new('abc', 'def') do |builder|
        builder.request :url_encoded
        builder.adapter :test do |stub|
          stub.get('/oauth2/v3/userinfo') { [200, { 'content-type' => 'application/json' }, '{"sub": "12345"}'] }
        end
      end
    end
    let(:access_token) { OAuth2::AccessToken.from_hash(client, {}) }

    before { allow(subject).to receive(:access_token).and_return(access_token) }

    describe 'id_token' do
      shared_examples 'id_token issued by valid issuer' do |issuer| # rubocop:disable Metrics/BlockLength
        context 'when the id_token is passed into the access token' do
          let(:token_info) do
            {
              'abc' => 'xyz',
              'exp' => Time.now.to_i + 3600,
              'nbf' => Time.now.to_i - 60,
              'iat' => Time.now.to_i,
              'aud' => subject.options.issuer,
              'iss' => issuer
            }
          end
          let(:id_token) { JWT.encode(token_info, 'secret') }
          let(:access_token) { OAuth2::AccessToken.from_hash(client, 'id_token' => id_token) }

          it 'should include id_token when set on the access_token' do
            expect(subject.extra).to include(id_token: id_token)
          end

          it 'should include id_info when id_token is set on the access_token and skip_jwt is false' do
            subject.options[:skip_jwt] = false
            expect(subject.extra).to include(id_info: token_info)
          end

          it 'should not include id_info when id_token is set on the access_token and skip_jwt is true' do
            subject.options[:skip_jwt] = true
            expect(subject.extra).not_to have_key(:id_info)
          end

          it 'should include id_info when id_token is set on the access_token by default' do
            expect(subject.extra).to include(id_info: token_info)
          end
        end
      end

      it_behaves_like 'id_token issued by valid issuer', 'https://auth.globus.org'
      
      context 'when the id_token is issued by an invalid issuer' do
        let(:token_info) do
          {
            'abc' => 'xyz',
            'exp' => Time.now.to_i + 3600,
            'nbf' => Time.now.to_i - 60,
            'iat' => Time.now.to_i,
            'aud' => 'appid',
            'iss' => 'fake.globus.org'
          }
        end
        let(:id_token) { JWT.encode(token_info, 'secret') }
        let(:access_token) { OAuth2::AccessToken.from_hash(client, 'id_token' => id_token) }

        it 'raises JWT::InvalidIssuerError' do
          expect { subject.extra }.to raise_error(JWT::InvalidIssuerError)
        end
      end

      context 'when the id_token is missing' do
        it 'should not include id_token' do
          expect(subject.extra).not_to have_key(:id_token)
        end

        it 'should not include id_info' do
          expect(subject.extra).not_to have_key(:id_info)
        end
      end
    end

    describe 'raw_info' do
      context 'when skip_info is true' do
        before { subject.options[:skip_info] = true }

        it 'should not include raw_info' do
          expect(subject.extra).not_to have_key(:raw_info)
        end
      end

      context 'when skip_info is false' do
        before { subject.options[:skip_info] = false }

        it 'should include raw_info' do
          expect(subject.extra[:raw_info]).to eq('sub' => '12345')
        end
      end
    end
  end

  # context 'info' do
  #   let(:params) { JSON.parse(IO.read(fixture_path + 'access_token.json')) }
  #   let(:access_token) { OpenStruct.new("params" => params) }
  #   let(:request_info) { JSON.parse(IO.read(fixture_path + 'request_info.json')) }

  #   before do
  #     allow(subject).to receive(:access_token).and_return(access_token)
  #     allow(subject).to receive(:request_info).and_return(request_info)
  #   end

  #   it 'should return name' do
  #     expect(subject.info[:name]).to eq('Martin Fenner')
  #   end

  #   it 'should return first_name' do
  #     expect(subject.info[:first_name]).to eq('Martin')
  #   end

  #   it 'should return last_name' do
  #     expect(subject.info[:last_name]).to eq('Fenner')
  #   end

  #   it 'should return description' do
  #     expect(subject.info[:description]).to start_with('Martin Fenner is the DataCite Technical Director')
  #   end

  #   it 'should return location' do
  #     expect(subject.info[:location]).to eq("DE")
  #   end

  #   it 'should return email' do
  #     expect(subject.info[:email]).to eq( "martin.fenner@datacite.org")
  #   end

  #   it 'should return urls' do
  #     expect(subject.info[:urls]).to eq([{"Blog"=>"http://blog.martinfenner.org"}])
  #   end
  # end

  # context 'raw_info' do
  #   let(:params) { JSON.parse(IO.read(fixture_path + 'access_token.json')) }
  #   let(:access_token) { OpenStruct.new("params" => params) }
  #   let(:request_info) { JSON.parse(IO.read(fixture_path + 'request_info.json')) }

  #   before do
  #     allow(subject).to receive(:access_token).and_return(access_token)
  #     allow(subject).to receive(:request_info).and_return(request_info)
  #   end

  #   it 'should not include raw_info' do
  #     subject.options[:skip_info] = true
  #     expect(subject.extra).not_to have_key(:raw_info)
  #   end

  #   it 'should return first_name' do
  #     expect(subject.extra.dig(:raw_info, :first_name)).to eq('Martin')
  #   end

  #   it 'should return last_name' do
  #     expect(subject.extra.dig(:raw_info, :last_name)).to eq('Fenner')
  #   end

  #   it 'should return other_names' do
  #     expect(subject.extra.dig(:raw_info, :other_names)).to eq(["Martin Hellmut Fenner"])
  #   end

  #   it 'should return description' do
  #     expect(subject.extra.dig(:raw_info, :description)).to start_with('Martin Fenner is the DataCite Technical Director')
  #   end

  #   it 'should return location' do
  #     expect(subject.extra.dig(:raw_info, :location)).to eq("DE")
  #   end

  #   it 'should return email' do
  #     expect(subject.extra.dig(:raw_info, :email)).to eq( "martin.fenner@datacite.org")
  #   end

  #   it 'should return urls' do
  #     expect(subject.extra.dig(:raw_info, :urls)).to eq([{"Blog"=>"http://blog.martinfenner.org"}])
  #   end

  #   it 'should return external_identifiers' do
  #     expect(subject.extra.dig(:raw_info, :external_identifiers)).to eq([{"type"=>"GitHub", "value"=>"mfenner", "url"=>"https://github.com/mfenner"}])
  #   end
  # end
end
