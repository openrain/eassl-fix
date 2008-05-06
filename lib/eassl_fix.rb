require 'eassl'

module EaSSL

  module Fix
    
    module SigningRequest
    
      def self.included(base)
        base.class_eval do
          alias_method_chain :ssl, :option_fix
        end
      end

      def ssl_with_option_fix
        unless @ssl
          @ssl = OpenSSL::X509::Request.new
          @ssl.version = 0
          @ssl.subject = CertificateName.new(@options[:name].options).ssl
          @ssl.public_key = key.public_key
          @ssl.sign(key.private_key, OpenSSL::Digest::MD5.new)
        end
        @ssl
      end
    end
    
  end

  class SigningRequest
    include EaSSL::Fix::SigningRequest
  end

  class CertificateName
    def options
      @options
    end
  end
  
end