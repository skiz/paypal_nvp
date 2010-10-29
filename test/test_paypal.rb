require File.dirname(__FILE__) + '/test_helper.rb'

include Paypal

class Test::Unit::TestCase
  
  protected
  
    def valid?(obj, &block)
      obj.valid?
      yield
    end
  
end

class PayPalExceptionTest < Test::Unit::TestCase
  
  def test_should_provide_custom_request_exception
    assert defined?(InvalidRequestException)
  end
  
  def test_should_provide_custom_validation_exception
    assert defined?(ValidationException)
  end
  
end

class PayPalAccountTest < Test::Unit::TestCase

  def test_should_set_username_and_password
    a = Account.new('username','password','-sig-')
    assert a.username = 'username'
    assert a.password = 'password'
  end

  def test_should_require_username
    a = Account.new('','password','-sig-')
    assert !a.valid?
    assert a.errors.on(:username)
  end

  def test_should_require_password
    a = Account.new('username','','-sig-')
    assert !a.valid?
    assert a.errors.on(:password)
  end
  
  def test_should_require_signature
    a = Account.new('username','password','')
    assert !a.valid?
    assert a.errors.on(:signature)
  end

end

class PayPalRequestBaseTest < Test::Unit::TestCase
  
  def setup
    @account = Account.new('user','pass','-sig-')
    @request = Request::Base.new(@account, :dryrun=> true)  
  end
  
  def test_should_be_able_to_set_dryrun_option
    assert @request.options[:dryrun] == true
    assert @request.dryrun? == true
  end
  
  def test_should_make_no_calls_and_return_no_content_when_dryrunning
    r = Request::Base.new(@account, :dryrun => true)
    assert r.response.is_a?(Paypal::ResponseHandler)
    assert r.response.errors.blank?
  end
  
  def test_should_set_default_url_option
    assert_equal 'api-3t.paypal.com', @request.options[:url]
  end
  
  def test_should_set_sandbox_url_with_option
    r = Request::Base.new(@account, :sandbox => true)
    assert_equal 'api-3t.sandbox.paypal.com', r.options[:url]
  end
    
end

class PayPalMassPayTest < Test::Unit::TestCase
  
  def setup
    @account = Account.new('login','pass','-sig-')
    @request = Request::MassPay.new(@account)
  end
  
  def test_should_provide_emailsubject
    assert @request.respond_to?(:emailsubject=)
  end
  
  def test_should_not_allow_over_255_length_email_subject
    @request.emailsubject = 'h'*256
    assert !@request.emailsubject.blank?
    valid?(@request) do
      assert @request.errors.on(:emailsubject)
    end
  end

  def test_should_require_valid_currency_code
    CURRENCY_CODES.each do |code, desc|
      @request.currencycode = code
      valid?(@request) do
        assert !@request.errors.on(:currencycode)
      end
    end
  end
  
  def test_should_require_valid_receivertype
    @request.receivertype = nil
    valid?(@request) do
      assert @request.errors.on(:receivertype)
    end
  end

  def test_should_disallow_ivalid_currency_code
    @request.currencycode = 'INV'
    valid?(@request) do
      assert @request.errors.on(:currencycode)
    end
  end
  
  def test_receivertype_should_allow_valid_entries
    ['EmailAddress','UserID'].each do |rt|
      @request.receivertype = rt
      valid?(@request) do
        assert !@request.errors.on(:receivertype)
      end      
    end
  end
  
  def test_masspay_should_require_valid_recipients
    r = Request::MassPayRecipient.new(
      :email => 'jack@testing.com',
      :amt => '1.00',
      :note => 'Here is your dollar.'
    )
    
    req = Request::MassPay.new(@account, :dryrun => true) do |m|
      m.currencycode = 'USD'     
      m.recipients = nil 
    end

    valid?(req) do
      assert req.errors.on(:recipients)
    end
     
  end
  
  def test_masspay_should_generate_clean_request_strings    
    m = Request::MassPay.new(@account, :dryrun => true)
    m.receivertype = 'EmailAddress'
    m.currencycode = 'USD'
    
    r = Request::MassPayRecipient.new(
      :email => 'jack@testing.com',
      :amt => '1.00',
      :note => 'Here is your dollar.'
    )
    
    assert m.recipients.blank?
    m.recipients << r
    m.recipients << r
    
    assert_match /CURRENCYCODE=USD&METHOD=MassPay&RECEIVERTYPE=EmailAddress&VERSION=51.0&L_EMAIL0/, m.request_string
    assert_match /L_EMAIL0=jack%40testing.com&L_AMT0=1.00&L_NOTE/, m.request_string
    assert_match /L_EMAIL1=jack%40testing.com&L_AMT1=1.00&L_NOTE/, m.request_string
  end    
  
end

class PayPalAddressVerifyTest < Test::Unit::TestCase

  def setup
    @account = Account.new('login','pass','-sig-')
    @request = Request::AddressVerify.new(@account)
  end
    
  def test_should_provide_default_request_method
    assert_equal('AddressVerify', Request::AddressVerify.new(@account).method)
  end
  
  def test_should_require_email_address
    valid?(@request) do
      assert @request.errors.on(:email)
    end
  end
   
  def test_should_allow_valid_email_addresses
    @request.email = "someguy@example.com"
    valid?(@request) do
      assert !@request.errors.on(:email)
    end
  end

  def test_should_require_street
    valid?(@request) do
      assert @request.errors.on(:street)
    end
  end

  def test_should_require_zip
    valid?(@request) do
      assert @request.errors.on(:zip)
    end
  end
  
  def test_should_allow_valid_zip
    @request.zip = '99999'
    valid?(@request) do
      assert !@request.errors.on(:zip)
    end
  end
  
  def test_should_not_allow_invalid_emails
    @request.email = 'something invalid yeah!'
    valid?(@request) do
      assert @request.errors.on(:email)
    end
  end

  def test_should_create_valid_request_object
    @request.email  = 'someguy@example.com'
    @request.street = '123 Testing Lane'
    @request.zip    = '99208'
    assert @request.valid?
  end

  def test_should_handle_block_initializer
    avr = Request::AddressVerify.new @account do |a|
      a.email  = 'jack@example.com'
      a.street = '123 Test Street'
      a.zip    = '99999'
    end
    assert avr.valid?
  end
  
  def test_should_have_correct_request_parameters
    assert_equal [:version, :method, :email, :street, :zip], @request.request_parameters
  end
  
  def test_provide_full_request_parameters
    r = Request::AddressVerify.new(@account) do |z|
      z.email  = 'joebob@aol.com'
      z.street = '123 Testing Lane'
      z.zip    = '99999'
    end
    assert_equal 'PWD=pass&USER=login&SIGNATURE=-sig-&EMAIL=joebob%40aol.com&METHOD=AddressVerify&STREET=123%20Testing%20Lane&VERSION=51.0&ZIP=99999', r.request_string
  end
  
end

class PayPalGetTrasactionDetailTest < Test::Unit::TestCase

  def setup
    @account = Account.new('login','pass','-sig-')
    @request = Request::GetTransactionDetails.new(@account)
  end
  
  def test_should_define_parameters_used_to_send_request
    assert_equal [:version, :method, :transactionid],  @request.request_parameters
  end
  
end

class PayPalGetBalanceTest < Test::Unit::TestCase

  def setup
    @account = Account.new('login','pass','-sig-')
    @request = Request::GetBalance.new(@account)
  end
    
  def test_should_provide_default_request_method
    assert_equal('GetBalance', Request::GetBalance.new(@account).method)
  end
       
  def test_all_should_be_false_by_default
    valid?(@request) do
      assert !@request.errors.on(:all)
      assert_equal @request.all, false
    end    
  end
  
  def test_should_allow_true_for_all
    @request.all = true
    valid?(@request) do
      assert !@request.errors.on(:all)
      assert_equal @request.all, true
    end    
  end
  
  def test_should_be_invalid_without_currency_option
    @request.all = nil
    valid?(@request) do
      assert @request.errors.on(:all)
    end
  end

  def test_should_handle_block_initializer
    gbr = Request::GetBalance.new @account do |a|
      a.all = true
    end
    assert gbr.valid?
  end
  
  def test_should_have_correct_request_parameters
    assert_equal [:version, :method, :returnallcurrencies], @request.request_parameters
  end
  
  def test_provide_full_request_parameters
    r = Request::GetBalance.new(@account) do |z|
      z.all = true
    end
    assert_equal 'PWD=pass&USER=login&SIGNATURE=-sig-&METHOD=GetBalance&RETURNALLCURRENCIES=1&VERSION=51.0', r.request_string
  end
  
end

class PayPalResponseTest < Test::Unit::TestCase
  
  def setup
    dfe = {:EMAIL=>"paypal_1230152961_per@webwideconsulting.com", :NETAMT=>"0.00", :TIMEZONE=>"GMT", :CURRENCYCODE=>"USD", :FEEAMT=>"-0.10", :TRANSACTIONID=>"1UD55086LJ102621M", :AMT=>"0.10", :TIMESTAMP=>"2009-01-02T20:14:03Z", :LNAME=>"Some Guy's Donations", :STATUS=>"Completed", :TYPE=>"Payment"}
    @response = Response.new(dfe)
  end
  
  def test_should_provide_dynamic_data_accessors
    assert @response.respond_to?(:email)
  end
  
  def test_should_handle_a_hash_from_data_for_elements
    dfe = {:EMAIL=>"paypal_1230152961_per@webwideconsulting.com", :NETAMT=>"0.00", :TIMEZONE=>"GMT", :CURRENCYCODE=>"USD", :FEEAMT=>"-0.10", :TRANSACTIONID=>"1UD55086LJ102621M", :AMT=>"0.10", :TIMESTAMP=>"2009-01-02T20:14:03Z", :LNAME=>"Some Guy's Donations", :STATUS=>"Completed", :TYPE=>"Payment"}
    Response.new(dfe)
  end
  
end

class PayPalResponseHandlerTest < Test::Unit::TestCase
  
  def setup
    @http_success = Net::HTTPOK.new(true, true, true)
    @failed_auth_string = "TIMESTAMP=2008%2d12%2d24T18%3a21%3a45Z&CORRELATIONID=667445c979c9&ACK=Failure&VERSION=51%2e0&BUILD=782942&L_ERRORCODE0=10002&L_SHORTMESSAGE0=Authentication%2fAuthorization%20Failed&L_LONGMESSAGE0=You%20do%20not%20have%20permissions%20to%20make%20this%20API%20call&L_SEVERITYCODE0=Error"
    @handler = ResponseHandler.new(@http_success, @failed_auth_string)
  end
    
  def test_should_raise_invalid_request_exception_without_a_net_http_response
    assert_raise InvalidRequestException do
      ResponseHandler.new('invalid_http_response')
    end
  end
  
  def test_should_raise_no_method_without_data
    assert_raise NoMethodError do
      @handler.foosadfsdafafdssdf
    end
  end
  
  def test_should_have_error_retrival_method
    assert @handler.respond_to?(:errors)
  end
  
  def test_should_provide_errors_when_provided
    assert_equal(1, @handler.errors.size)
  end
  
  def test_should_be_invalid_with_errors
    assert_equal(1, @handler.errors.size)
    assert_equal(false, @handler.valid?)
  end
  
  def test_should_provide_multiple_responses_when_available
    
    custom_string = "L_TIMESTAMP0=2009%2d01%2d02T20%3a14%3a03Z&L_TIMEZONE0=GMT&\
    L_TYPE0=Payment&L_EMAIL0=paypal_1230152961_per%40webwideconsulting%2ecom&\
    L_NAME0=Some%20Guy%27s%20Donations&L_TRANSACTIONID0=1UD55086LJ102621M&\
    L_STATUS0=Completed&L_AMT0=0%2e10&L_CURRENCYCODE0=USD&\
    L_FEEAMT0=%2d0%2e10&L_NETAMT0=0%2e00".gsub(/\s+/,'')
    
    assert custom_string
    
    # duplicate the request string so we have 2 entries
    custom_string += '&' + custom_string.gsub(/(L_\w+)(0)/i, '\11')
    @handler = ResponseHandler.new(@http_success, custom_string)
    assert_equal true, @handler.valid?
    assert_equal 2, @handler.responses.size
  end
  
  def test_should_not_be_successful_if_ack_is_failure
    custom_string = 'ACK=Failure'
    @handler = ResponseHandler.new(@http_success, custom_string)
    assert @handler.valid?
    assert !@handler.success?
  end
end

class PayPalErrorTest < Test::Unit::TestCase
  
  def setup
    @err = Error.new('error_code', 'short_message', 'long_message', 'severity_code')
  end
  
  def test_should_have_error_code
    assert_equal(@err.error_code, 'error_code')
  end
  
  def test_should_have_short_message
    assert_equal(@err.short_message, 'short_message')
  end
  
  def test_should_have_long_message
    assert_equal(@err.long_message, 'long_message')
  end
  
  def test_should_have_severity_code
    assert_equal(@err.severity_code, 'severity_code')
  end
  
  def test_should_provide_long_message_as_string
    assert_equal(@err.to_s, 'long_message')
  end
  
end

class PayPalTransactionSearchTest < Test::Unit::TestCase
  
  def setup
    @account = Account.new('login','pass','-sig-')
    @request = Request::TransactionSearch.new(@account)
  end
  
  def test_should_have_only_complete_attributes
    # @request.invnum = 45
    # assert_equal [:version, :method, :invnum], @request.define_parameters
  end
  
  def test_should_require_startdate
    @request.startdate = nil
    valid?(@request) do
      assert @request.errors.on(:startdate)
    end
  end
  
  def test_should_correctly_generate_utc_time_string_and_encode
    @request.startdate = Date.new(2009,1,1)
    assert_match(/STARTDATE=2009-01-01%090%3A00%3A00%09%2B00%3A00&/, @request.request_string)
  end
  
end
 
class PayPalSandBoxTest < Test::Unit::TestCase
  
  def setup
    @buyer_account = Account.new(
      'username',
      'pass',
      'cert')
      
    @seller_account = Account.new(
      'username',
      'pass',
      'cert')
  end
  
  def test_passes_when_commented_out_actual_requests_below
    assert true
  end

## These are live tests that need to be handled differently
  # def test_get_transaction_info_in_sandbox
  #   # id = '1UD55086LJ102621M'
  #   # @request = Request::GetTransactionDetails.new(@seller_account, :sandbox => true) do |r|
  #   #   r.transactionid = id
  #   # end
  #   # puts @request.response.inspect    
  # end
# 
#   def test_get_balance_in_sandbox
#     @request = Request::GetBalance.new(@seller_account, :sandbox => true) do |r|
#       r.all = false
#     end
#    puts @request.response.responses.inspect
#     #assert @request.response.is_a?(Response), 'should be a response not handler'
#   end
# 
#   def test_transaction_search_for_clean_transactions
#     @request = Request::TransactionSearch.new(@seller_account, :sandbox => true) do |r|
#       r.startdate = 2.days.ago
#       r.transactionclass = 'Received'
#       r.status = 'Success'      
#     end    
# #    throw @request.request_string
#     puts @request.response.responses.inspect
#   end  
  
  # def test_simple_polling_for_verify_and_send_back_funds
  #   #3.times do
  # 
  #   pending_emails = ['paypal_1230152961_per@webwideconsulting.com']
  #   puts pending_emails
  # 
  #   last_run = 6.days.ago
  #   @request = Request::TransactionSearch.new(@seller_account, :sandbox => true) do |r|
  #     r.startdate = last_run
  #     r.transactionclass = 'Received'
  #     r.status = 'Success'
  #   end
  #   last_run = Time.now
  #   @request.response.responses.each do |resp|
  #     # does this one belong to a pending verification?
  #     if pending_emails.include?(resp.email)
  #       puts 'found transaction for ' + resp.email
  #       # verify that they are a verified user and transaction detail is sane
  #       vr = Request::GetTransactionDetails.new(@seller_account, :sandbox => true) do |r|
  #         r.transactionid = resp.transactionid
  #       end
  #       if vr.response.payerstatus.downcase != 'verified'
  #         puts 'Not handling this transaction (unverified account)'
  #       elsif vr.response.paymentstatus.downcase != 'completed'
  #         puts 'Not handling this transaction (incomplete transaction)'
  #       else
  #         puts 'Trying to send the money back...'
  #         # seems to be sane enough.... lets send it back and mark them not pending
  #           masspay = Request::MassPay.new(@seller_account, :sandbox => true) do |r|
  #             r.emailsubject = 'Testing'
  #             r.currencycode = 'USD'
  #             r.receivertype = 'UserID'
  #           end            
  #           rec = Request::MassPayRecipient.new(
  #             :receiverid => vr.response.payerid,
  #             :amt => resp.amt
  #           )
  #           masspay.recipients << rec
  #           
  #           puts "Sending #{resp.amt} to #{vr.response.payerid} (#{resp.email})"
  #           puts masspay.request_string
  #           puts masspay.response.inspect
  #           puts masspay.response.success?
  #       end
  #     else
  #       puts 'no pending emails for validation in any transactions.'
  #     end
  #   end
  # end
   
end
