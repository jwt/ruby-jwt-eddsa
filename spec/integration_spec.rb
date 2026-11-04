# frozen_string_literal: true

require "securerandom"

RSpec.describe "Usage via ruby-jwt" do
  let(:private_key) { Ed25519::SigningKey.new("b" * 32) }
  let(:public_key) { private_key.verify_key }

  let(:payload) { { "pay" => "load" } }

  describe "encoding and decoding" do
    context "when encoding and decoding keys match" do
      it "executes successfully" do
        token = JWT.encode(payload, private_key, "EdDSA")
        expect(JWT.decode(token, public_key, true, algorithm: "EdDSA"))
          .to eq([payload, { "alg" => "EdDSA" }])
      end
    end

    context "when encoding with ED25519" do
      it "executes successfully" do
        token = JWT.encode(payload, private_key, "ED25519")
        expect(JWT.decode(token, public_key, true, algorithm: "EdDSA"))
          .to eq([payload, { "alg" => "EdDSA" }])
      end
    end

    context "when decoding key is wrong" do
      let(:public_key) { Ed25519::SigningKey.new("a" * 32).verify_key }
      it "raises decoding error" do
        token = JWT.encode(payload, private_key, "EdDSA")

        expect do
          JWT.decode(token, public_key, true, algorithm: "EdDSA")
        end.to raise_error(JWT::DecodeError, "Signature verification failed")
      end
    end

    context "when decoding with a private key" do
      it "raises decoding error" do
        token = JWT.encode(payload, private_key, "EdDSA")

        expect do
          JWT.decode(token, private_key, true, algorithm: "EdDSA")
        end.to raise_error(JWT::DecodeError)
      end
    end

    context "when encoding with a public key" do
      it "raises encoding error" do
        expect do
          JWT.encode(payload, public_key, "EdDSA")
        end.to raise_error(JWT::EncodeError)
      end
    end
  end

  describe "RFC 9864 Ed25519 algorithm name" do
    let(:token) { JWT.encode(payload, private_key, "Ed25519", { alg: "Ed25519" }) }

    it "keeps the EdDSA header unless Ed25519 is requested" do
      %w[EdDSA Ed25519 ED25519].each do |algorithm|
        header = JWT::EncodedToken.new(JWT.encode(payload, private_key, algorithm)).header
        expect(header).to eq("alg" => "EdDSA")
      end
    end

    it "signs with the Ed25519 header when given" do
      expect(JWT::EncodedToken.new(token).header).to eq("alg" => "Ed25519")
    end

    it "verifies an Ed25519 token when Ed25519 is allowed" do
      expect(JWT.decode(token, public_key, true, algorithms: ["Ed25519"]))
        .to eq([payload, { "alg" => "Ed25519" }])
      expect(JWT.decode(token, public_key, true, algorithms: %w[EdDSA Ed25519]).first).to eq(payload)
    end

    it "accepts both names when both are allowed" do
      eddsa_token = JWT.encode(payload, private_key, "EdDSA")
      expect(JWT.decode(eddsa_token, public_key, true, algorithms: %w[EdDSA Ed25519]).first).to eq(payload)
    end

    it "rejects an Ed25519 token when only EdDSA is allowed" do
      expect do
        JWT.decode(token, public_key, true, algorithms: ["EdDSA"])
      end.to raise_error(JWT::IncorrectAlgorithm)
    end

    it "verifies with a JWKS" do
      jwk = JWT::JWK.new(private_key, kid: "ed25519-key")
      token = JWT.encode(payload, private_key, "Ed25519", { alg: "Ed25519", kid: jwk.kid })

      [jwk.export, jwk.export.merge(alg: "Ed25519")].each do |public_jwk|
        decoded, = JWT.decode(token, nil, true, algorithms: ["Ed25519"], jwks: { keys: [public_jwk] })
        expect(decoded).to eq(payload)
      end
    end

    it "resolves a JWK with alg Ed25519 to the Ed25519 algorithm" do
      jwk = JWT::JWK.import(JWT::JWK.new(public_key).export.merge(alg: "Ed25519"))
      expect(jwk.jwa.alg).to eq("Ed25519")
      expect(jwk.jwa.valid_alg?("ED25519")).to eq(true)
    end
  end

  describe "OKP JWK usage" do
    let(:jwk)           { JWT::JWK.new(Ed25519::SigningKey.new(SecureRandom.hex)) }
    let(:public_jwks)   { { keys: [jwk.export, { kid: "not_the_correct_one", kty: "oct", k: "secret" }] } }
    let(:signed_token)  { JWT.encode(token_payload, jwk.signing_key, "EdDSA", token_headers) }
    let(:token_payload) { { "data" => "something" } }
    let(:token_headers) { { kid: jwk.kid } }

    it "decodes the token" do
      key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
      payload, _header = JWT.decode(signed_token, nil, true,
                                    { algorithms: ["EDDSA"], jwks: key_loader })
      expect(payload).to eq(token_payload)
    end

    it "rejects an Ed25519 key labelled as X25519" do
      public_jwks[:keys].first[:crv] = "X25519"

      expect do
        JWT.decode(signed_token, nil, true, algorithms: ["EdDSA"], jwks: public_jwks)
      end.to raise_error(JWT::JWKError, /Incorrect 'crv' value/)
    end

    context "with a mixed JWKS" do
      let(:public_jwks) do
        { keys: [
          { kty: "OKP", crv: "X25519", use: "enc", kid: "encryption",
            x: Base64.urlsafe_encode64("x" * 32, padding: false) },
          { kty: "OKP", crv: "Ed448", kid: "ed448", x: Base64.urlsafe_encode64("x" * 57, padding: false) },
          jwk.export
        ] }
      end

      it "verifies with the selected Ed25519 key" do
        payload, _header = JWT.decode(signed_token, nil, true, algorithms: ["EdDSA"], jwks: public_jwks)
        expect(payload).to eq(token_payload)
      end

      it "rejects selecting an unsupported curve for EdDSA" do
        token = JWT.encode(token_payload, jwk.signing_key, "EdDSA", kid: "ed448")

        expect do
          JWT.decode(token, nil, true, algorithms: ["EdDSA"], jwks: public_jwks)
        end.to raise_error(JWT::JWKError, /Incorrect 'crv' value/)
      end

      it "exports the whole set" do
        expect(JWT::JWK::Set.new(public_jwks).export).to eq(public_jwks)
      end
    end
  end

  describe "JWK as key" do
    let(:jwk) { JWT::JWK.new(Ed25519::SigningKey.new(SecureRandom.hex)) }

    it "signs and verifies using the jwk" do
      token = JWT::Token.new(payload: {}, header: {})

      token.sign!(algorithm: "EdDSA", key: jwk)

      encoded_token = JWT::EncodedToken.new(token.jwt)
      encoded_token.verify!(signature: { algorithm: %w[HS256 EdDSA], key: jwk })
    end
  end
end
