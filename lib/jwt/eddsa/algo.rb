# frozen_string_literal: true

module JWT
  module EdDSA
    # EdDSA algorithm implementation
    class Algo
      include JWT::JWA::SigningAlgorithm

      def initialize(alg)
        @alg = alg
      end

      def sign(data:, signing_key:)
        unless signing_key.is_a?(Ed25519::SigningKey)
          raise_sign_error!("Key given is a #{signing_key.class} but needs to be a Ed25519::SigningKey")
        end

        signing_key.sign(data)
      end

      def verify(data:, signature:, verification_key:)
        unless verification_key.is_a?(Ed25519::VerifyKey)
          raise_verify_error!("Key given is a #{verification_key.class} but needs to be a Ed25519::VerifyKey")
        end

        verification_key.verify(signature, data)
      rescue Ed25519::VerifyError
        false
      end

      # Tokens are signed with the "EdDSA" header by default, for compatibility
      # with verifiers that only accept the RFC 8037 name. Pass the header
      # { alg: "Ed25519" } when encoding to use the RFC 9864 name instead.
      def header(*)
        { "alg" => "EdDSA" }
      end

      register_algorithm(new("EdDSA"))
      # The RFC 9864 name. Lookups are case-insensitive, so "ED25519" (the name
      # used by ruby-jwt 2.x) resolves to the same algorithm.
      register_algorithm(new("Ed25519"))
    end
  end
end
