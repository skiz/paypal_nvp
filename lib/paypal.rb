$:.unshift(File.dirname(__FILE__)) unless
  $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

require 'uri'
require 'net/https'
require 'rubygems'
require 'validatable'
require 'activesupport'

# = Paypal NVP
module Paypal
  VERSION = '0.0.1'
  
  require 'uri'
  require 'net/https'
  require 'rubygems'
  require 'validatable'
  require 'activesupport'


    # Currencies supported by PayPal
    CURRENCY_CODES = {
      :AUD => 'Australian Dollar',
      :CAD => 'Canadian Dollar',
      :CZK => 'Czech Koruna',
      :DKK => 'Danish Krone',
      :EUR => 'Euro',
      :HKD => 'Hong Kong Dollar',
      :HUF => 'Hungarian Forint',
      :ILS => 'Israeli New Sheqel',
      :JPY => 'Japanese Yen',
      :MXN => 'Mexican Peso',
      :NOK => 'Norwegian Krone',
      :NZD => 'New Zealand Dollar',
      :PLN => 'Polish Zloty',
      :GBP => 'Pound Sterling',
      :SGD => 'Singapore Dollar',
      :SEK => 'Swedish Krona',
      :CHF => 'Swiss Franc',
      :USD => 'U.S. Dollar'
    }.freeze

    # State/Province codes supported by PayPal
    STATE_AND_PROVINCE_CODES = {
      :AB => 'Alberta',
      :BC => 'British Columbia',
      :MB => 'Manitoba',
      :NB => 'New Brunswick',
      :NL => 'Newfoundland and Labrador',
      :NT => 'Northwest Territories',
      :NS => 'Nova Scotia',
      :NU => 'Nunavut',
      :ON => 'Ontario',
      :PE => 'Prince Edward Island',
      :QC => 'Quebec',
      :SK => 'Saskatchewan',
      :YT => 'Yukon',
      :AL => 'Alabama',
      :AK => 'Alaska',
      :AS => 'American Samoa',
      :AZ => 'Arizona',
      :AR => 'Arkansas',
      :CA => 'California',
      :CO => 'Colorado',
      :CT => 'Connecticut',
      :DE => 'Delaware',
      :DC => 'District of Columbia',
      :FM => 'Federated States of Micronesia',
      :FL => 'Florida',
      :GA => 'Georgia',
      :GU => 'Guam',
      :HI => 'Hawaii',
      :ID => 'Idaho',
      :IL => 'Illinois',
      :IN => 'Indiana',
      :IA => 'Iowa',
      :KS => 'Kansas',
      :KY => 'Kentucky',
      :LA => 'Louisiana',
      :ME => 'Maine',
      :MH => 'Marshall Islands',
      :MD => 'Maryland',
      :MA => 'Massachusetts',
      :MI => 'Michigan',
      :MN => 'Minnesota',
      :MS => 'Mississippi',
      :MO => 'Missouri',
      :MT => 'Montana',
      :NE => 'Nebraska',
      :NV => 'Nevada',
      :NH => 'New Hampshire',
      :NJ => 'New Jersey',
      :NM => 'New Mexico',
      :NY => 'New York',
      :NC => 'North Carolina',
      :ND => 'North Dakota',
      :MP => 'Northern Mariana Islands',
      :OH => 'Ohio',
      :OK => 'Oklahoma',
      :OR => 'Oregon',
      :PW => 'Palau',
      :PA => 'Pennsylvania',
      :PR => 'Puerto Rico',
      :RI => 'Rhode Island',
      :SC => 'South Carolina',
      :SD => 'South Dakota',
      :TN => 'Tennessee',
      :TX => 'Texas',
      :UT => 'Utah',
      :VT => 'Vermont',
      :VI => 'Virgin Islands',
      :VA => 'Virginia',
      :WA => 'Washington',
      :WV => 'West Virginia',
      :WI => 'Wisconsin',
      :WY => 'Wyoming',
      :AA => 'Armed Forces Americas',
      :AE => 'Armed Forces',
      :AP => 'Armed Forces Pacific'
    }.freeze


    # When we are unable to access the API due to either authentication
    # or other network error, an InvalidRequestException should be raised.
    class InvalidRequestException < Exception ; end

    # When a required validation fails, a ValidationException should be raised
    class ValidationException < Exception ; end

    # When API errors are returned, we create error objects for easier handling.
    #
    # Example:
    #  err = Error.new(1005, 'No Data', 'There was no data available', 'SOMECODE')
    #  err.to_s # => 'There was no data available'
    class Error
      attr_reader :error_code, :short_message, :long_message, :severity_code

      # Create a new Error instance with the provided parameters.
      def initialize(error_code, short_message, long_message, severity_code)
        @error_code, @short_message, @long_message, @severity_code =
          error_code, short_message, long_message, severity_code
      end

      # Returns the long_message for human readability
      def to_s
        self.long_message
      end

    end

    # The authenticated account that is used to access the API. This can be
    # an actual API account, or a sandbox account. All 3 parameters are required.
    # <b>Every request requires that the account is provided as the first parameter.</b>
    #
    # Example:
    #  account = Account.new('username','password','signature')
    #
    class Account
      include Validatable
      attr_accessor :username, :password, :signature
      validates_presence_of :username, :password, :signature

      # Create a PayPal account instance for service authentication
      def initialize(username, password, signature)
        @username, @password, @signature = username, password, signature
      end
    end

    # A proxy which provides handling generation of responses
    # If there is more than 1 response, responses will return an
    # array with all of the responses otherwise we return a single Response
    class ResponseHandler #:nodoc:#
      attr_reader :errors, :data, :http_response, :responses

      # [#<Net::HTTPOK 200 OK readbody=true>, "nvp=true"]
      def initialize(resp, line_data='')
        @errors = []
        raise InvalidRequestException.new('Missing HTTP Response') unless resp.is_a?(Net::HTTPResponse)
        @data, @http_response, @responses = {}, resp, []

        # Turn the response data in to a suitable data hash
        line_data.split('&').collect do |n|
          k,v = n.split('='); 
          @data[URI.decode(k).to_sym] = URI.decode(v)
        end

        # Check for any errors and create request centric error objects
        (0..100).each do |cnt| 
          if @data["L_ERRORCODE#{cnt}".to_sym]
            @errors ||= []
            @errors << Error.new(
              @data["L_ERRORCODE#{cnt}".to_sym],
              @data["L_SHORTMESSAGE#{cnt}".to_sym],
              @data["L_LONGMESSAGE#{cnt}".to_sym],
              @data["L_SEVERITYCODE#{cnt}".to_sym]
            )
          else ; break
          end
        end

        # create a set of responses from the data provided
        # maximum of 100 elements handled.
        (0..100).each do |cnt|
          @dfe = data_for_elements(cnt)
          break if @dfe.blank?  
          @responses << Response.new(@dfe)
        end

        # define some methods from the attributes
        # a better alternative than using method_missing
        # Example:  @data[:TIMESTAMP] is #timestamp method
        @data.keys.each do |var|
          (class << self ; self ; end).class_eval do
            define_method var.to_s.downcase.gsub('_','') do
              @data[var]
            end
          end
        end      


      end

      # Looks like we got a valid http response if we get a successful HTTP response
      # in the 2xx range and there are no errors available.
      def valid?
        @http_response.is_a?(Net::HTTPSuccess) && @errors.blank?
      end

      # If the request was a failure or invalid, this will return false.
      def success?
        valid? && ack != 'Failure'
      end

      protected

      # return the elements from the data with the response id
      # used when there are multiple responses by way of 
      # L_TIMESTAMP#{id} for example, using ID to find the rest 
      # of the elements.
      def data_for_elements(id) #:nodoc:#
        # only pull elements with the keyed id
        trans1 = @data.reject{|k,s| k.to_s.split('').last != id.to_s }
        # remove the elements id and prefix /L_(\w+){#id}/
        trans2 = {}
        trans1.each{|k,s| trans2["#{k}".gsub(/^L_/,'').gsub(/#{id}$/,'')] = s }
        trans2.symbolize_keys
      end
    end

    # A response object which provides data that is received.
    # All accessors are handled dynamically by creating methods
    # This is nothing more than a dynamic presenter for the data.
    #
    #
    class Response

      attr_reader :data #:nodoc:#

      # You should be passing in a hash that is already converted
      # to receive clean attributes.
      #
      # Example:
      #  r = Response.new({:EMAIL=>"joe@example.com", :NETAMT=>"0.00"})
      #  r.email # => 'joe@example.com'
      def initialize(data={})
        @data = data

        # define some methods from the attributes
        # a better alternative than using method_missing
        # Example:  @data[:TIMESTAMP] is #timestamp method
        @data.keys.each do |var|
          (class << self ; self ; end).class_eval do
            define_method var.to_s.downcase.gsub('_','') do
              @data[var]
            end
          end
        end      
      end
    end

    module Request #:nodoc:#

      # These are the default options that can be changed when 
      DEFAULT_OPTIONS = {
        :dryrun  => false,
        :sandbox => false,
        :url     => 'api-3t.paypal.com'
      }

      # All requests handlers extend Request::Base and the class <b>must be named
      # the same as the API call which is being requested</b>.
      #
      # To create a new API request object you must simply extend Request::Base, add the 
      # attribute accesors, set the request_parameters, and add any validation.
      #
      # Note: By default the Method is set as the class name, and the version is passed.
      #
      # Simple Pseudo Example:
      #
      #  class VerifyEmail < Request::Base
      #    attr_accessor :email
      #    validates_presence_of :email
      #    
      #    def define_parameters
      #      @request_parameters = [:version, :method, :email]
      #    end
      #  end
      #
      class Base
        include Validatable
        API_VERSION = '51.0'

        attr_reader :options, :request_parameters

        # Create a new request object. Also supports block initialization
        # for clarity.
        #
        # Example:
        #  AddressVerify.new @account do |av|
        #    av.email  = 'someone@example.com'
        #    av.street = '123 Main Street'
        #    av.zip    = '12345'
        #  end
        def initialize(account, opts={}, &block)
          @account = account
          @options = DEFAULT_OPTIONS.merge(opts)
          @options[:url] = "api-3t.sandbox.paypal.com" if @options[:sandbox]
          define_parameters
          yield self if block_given?
        end

        # Provides a request string for passing along to the PayPal NVP service.
        # This uses all of the @request_parameters along with the account authentication
        # string to make a valid request string.
        def request_string
          "#{authentication_string}&" + @request_parameters.
          reject{|k| self.send(k).blank?}.map(&:to_s).sort.map{|k|
            "#{k.to_s.upcase}=#{escape(self.send(k))}"
          }.flatten.join('&')
        end

        # Provides a string which is used as part of th request_string when generating
        # requests
        def authentication_string
          pwd  = escape(@account.password)
          user = escape(@account.username)
          sig  = escape(@account.signature) 
          "PWD=#{pwd}&USER=#{user}&SIGNATURE=#{sig}"
        end

        # Provides the method used in the request string generation
        # This ends up being the name of the request class
        def method
          self.class.name.split('::').last || ''
        end

        # Provides the version used in the request string generation
        def version
          raise InvalidRequestException unless defined?(API_VERSION)
          API_VERSION
        end

        # Make the remote request and return a Response object
        def response
          http = Net::HTTP.new(@options[:url], 443)
          http.use_ssl = true
          path = '/nvp'
          headers = {
            'Content-Type' => 'application/x-www-form-urlencoded'
          }

          # dryrun support, provides a 204 which is success without content
          return ResponseHandler.new(
            Net::HTTPNoContent.new(true, true,true)
          ) if dryrun?

          # request caching
          silence_warnings do
            return @cached_response if @cached_response
            resp, data = http.post(path, request_string, headers)
            @cached_response = ResponseHandler.new(resp, data)
          end
        end

        # Is this request actually going to make the remote calls
        # or are we just going to return a mock 204 response.
        def dryrun?
          !!@options[:dryrun]
        end

        protected

        def define_parameters
          @request_parameters = []
        end

        protected

        # Quick URI Escape with some simple data type transposing 
        def escape(str)
          str = str.to_date.strftime("%Y-%m-%d\t0:00:00\t%Z") if 
            [Date, DateTime, Time].include?(str.class)
          URI.escape(str.to_s, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
        end

      end

      # Confirms whether a postal address and postal code match those
      # of the specified PayPal account holder.
      #
      # Required Attributes:
      # - email
      # - street
      # - zip
      #
      # <b>Note: Must be enabled manually by an account manager</b>
      #
      class AddressVerify < Request::Base

        attr_accessor :email, :street, :zip

        def define_parameters #:nodoc:#
          @request_parameters = [:version, :method, :email, :street, :zip]
        end

        validates_presence_of :email, :street, :zip, :level => 1
        validates_format_of :email, :with => /^[\w\.=-]+@[\w\.-]+\.[\w]{2,3}$/
        validates_length_of :email, :maximum => 255
        validates_format_of :street, :with => /[ a-zA-Z \-\,\.\'\#\\]+/
        validates_length_of :street, :within => 3..35
        validates_length_of :zip, :within => 5..16
      end

      # Get the details of a transaction via the API
      #
      # Required Attributes:
      # - transactionid (string) <em>The transaction id</em>
      #
      class GetTransactionDetails < Request::Base
        attr_accessor :transactionid

        def define_parameters  #:nodoc:#
          @request_parameters = [:version, :method, :transactionid]
        end
        validates_presence_of :transactionid
        validates_length_of :transactionid, :maximum => 17
        validates_format_of :transactionid, :with => /^[a-z0-9]+$/i

      end

      # Get the API user's balance of funds in their account
      #
      # Optional Attributes:
      # - all (true or false) <em>Provides all holding currencies or the default currency.</em> false by default
      #
      class GetBalance < Request::Base
        attr_accessor :all 

        protected
        def define_parameters  #:nodoc:#
          @all = false # by default
          @request_parameters = [:version, :method, :returnallcurrencies]
        end

        def returnallcurrencies #:nodoc:#
          @all ==  true ? 1 : 0
        end

        validates_presence_of :all
        validates_format_of :returnallcurrencies, :with => /[01]/
      end

      # Search transaction history for transactions that meet the specified criteria.
      #
      # Required Attributes:
      # - startdate
      # - Any other attribute used as search term
      #
      class TransactionSearch < Request::Base
        attr_accessor :startdate, :enddate, :email, :receiver, :receiptid,
                      :transactionid, :invnum, :acct, :auctionitemnumber,
                      :transactionclass, :amt, :currencycode, :status

        protected
        # not exactly DRY, need to add an #attributes method
        def define_parameters  #:nodoc:#
          @request_parameters =  [:version, :method,  :startdate, :enddate,
                                  :email, :receiver, :receiptid,
                                  :transactionid, :invnum, :acct, :auctionitemnumber,
                                  :transactionclass, :amt, :currencycode, :status]
        end

        validates_presence_of :startdate
        validates_format_of :email, :with => /$|^[\w\.=-]+@[\w\.-]+\.[\w]{2,3}$/
        validates_length_of :email, :within => 0..127
        # TODO: Add more validations per item
      end


      # Request to make a payment to one or more PayPal account holders represented
      # by MassPayRecipient instances.  When selecting receiver type, only provide
      # either EmailAddress or UserID but not both, and all MassPayRecipients must
      # only have EmailAddress or UserID defined as to match. 
      #
      # Required Attributes:
      # - currencycode (CURRENCY_CODES) <em>The selected currency transactions will be handled in</em>
      # - receivertype (EmailAddress or UserID) <em>All MassPayRecipient being used should also have this attribute set</em>
      #
      # Optional Attributes:
      # - emailsubject (string) <em>A subject for the email which PayPal sends each receiver</em>
      #
      # Example:
      #
      #  masspay = MassPay.new(@account, :sandbox => true) do |mp|
      #    mp.emailsubject = 'Your payment has been sent'
      #    mp.currencycode = 'USD'
      #    mp.receivertype = 'EmailAddress'
      #  end
      #  masspay.recipients = [recipient1, recipent2, ...]
      #  response = masspay.response
      #
      class MassPay < Request::Base
        attr_accessor :emailsubject, :currencycode, :receivertype, :recipients

        validates_length_of :emailsubject, :maximum => 255
        validates_true_for  :currencycode, :logic => lambda { currencycode && CURRENCY_CODES.keys.include?(currencycode.to_sym) }
        validates_true_for  :receivertype, :logic => lambda { ['EmailAddress','UserID'].include?(receivertype)}
        validates_true_for  :recipients,   :logic => lambda { !recipients.blank? }
        
        def define_parameters
          @request_parameters = [:version, :method, :emailsubject, :currencycode, :receivertype]
        end

        # Sets the recipients to an empty array by default
        def initialize_with_defaults(account, opts={}, &block) #:nodoc:#
          @recipients = []
          initialize_without_defaults(account, opts={}, &block)
        end
        alias_method_chain :initialize, :defaults
        
        # Adds all of the recipients to the request string
        def request_string_with_recipients #:nodoc:#
          rec_strings = []
          recipients.each_with_index do |r, id|
            rec_strings <<  r.request_parameters.map{ |param, val|
              "L_#{param.to_s.upcase}#{id}=#{escape(val)}"
            }
          end
          request_string_without_recipients + '&' + rec_strings.flatten.join('&')
        end        
        alias_method_chain :request_string, :recipients
        
      end

      # To define to whom payments will be sent to, you can create
      # a MassPayRecipient for each payment used as recipients in
      # the MassPay request
      #
      # Optional Attributes:
      # - emailsubject (String) <em>A customized email subject for the recipient</em>
      # - unique (String) <em>Internal accounting reference for the payment</em>
      # - note (String) <em>A note for this payment that should be recorded</em>
      #
      # Required Attributes:
      # - currencycode (CURRENCY_CODES) <em>The currency in which the amount will be sent</em>
      # - receivertype ('EmailAddress' or 'UserID') <em>One or the other must be selected</em>
      # - amt (String ##.## Format) <em>The amount in which to send</em>
      # - 
      #
      # Example:
      #   MassPayRecipient.new(:email => 'joe@example.com', :amt => '5.00', :unique => '0001', :note => 'Your account is now active')
      #
      class MassPayRecipient
        include Validatable
        attr_accessor :email, :receiverid, :amt, :unique, :note

        # TODO: Validate either receiverid or email provided
        validates_presence_of :amt
        validates_length_of :note, :maximum => 4000
        validates_true_for :email, :logic => lambda { [email, receiverid].any? && ![email, receiverid].all? }, 
                                   :message => 'You must provide either email or receiverid but not both'


        def initialize(attrs = {})
          attrs.each{|k,v| self.send("#{k}=", v) }
        end

        # Provides the attributes for MassPay to be able to generate
        # the additional request string parameters.
        def request_parameters
          {:email => @email, :receiverid => @receiverid, :amt => @amt,
           :uniqueid => @unique, :note => @note}.reject{|k,v| v.nil? }
        end
      end

    end
end