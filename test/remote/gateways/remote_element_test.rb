require 'test_helper'

class RemoteElementTest < Test::Unit::TestCase
  module NullProcessor
    # The below table works with the following transaction types:
    # CreditCardSale, CreditCardAuthorization, CreditCardCredit, CreditCardReturn, DebitCardSale and DebitCardReturn
    CARD_CODED_VALUES = {
      # code: Dollar Amount # [Express Response Code/Message], # Host Response Code/Message
              approved:   100, # [0, 'APPROVED'],           # 000 / AP
      partial_approved:  2305, # [5, 'PARTIAL APPROVED'],   # 010 / PARTIAL AP
              declined:    20, # [20, 'DECLINED'],          # 007 / DECLINED
          expired_card:    21, # [21, 'EXPIRED CARD'],      # 054 / EXPIRED CARD
          duplicate_ap:    22, # [22, 'DUPLICATE AP'],      # 094 / AP DUP
             duplicate:    23, # [23, 'DUPLICATE'],         # 094 / DUPLICATE
          pick_up_card:    24, # [24, 'PICK UP CARD'],      # 004 / PICK UP CARD
           call_issuer:    25, # [25, 'CALL ISSUER'],       # 002 / CALL ND
             undefined:    90, # [90, 'UNDEFINED'],
          invalid_data:   101, # [101, 'INVALID DATA'],
       invalid_account:   102, # [102, 'INVALID ACCOUNT'],
       invalid_request:   103, # [103, 'INVALID REQUEST'],
           auth_failed:   104, # [104, 'AUTH FAILED'],
           not_allowed:   105, # [105, 'NOT ALLOWED'],      # 058 / UNAUTH TRANS
        out_of_balance:   120, # [120, 'OUT OF BALANCE'],   # 0NB / INV BAL/SETTL
            comm_error:  1001, # [1001, 'COMM ERROR'],
            host_error:  1002, # [1002, 'HOST ERROR'],
                 error:  1009, # [1009, 'ERROR'],
      balance_approved:  2306, # [0, 'APPROVED'],           # 000 / AP (Balance and Currency returned)
      any_other_amount:  9999, # [0 / APPROVED],            # 000 / AP
    }

    def self.card_code_amount(symbol)
      CARD_CODED_VALUES[symbol]
    end
  end

  def setup
    @gateway = ElementGateway.new(fixtures(:element))

    @amount = NullProcessor.card_code_amount(:approved)
    # Element lists certain amounts that can be used
    # for triggering certain results.
    @declined_amount = NullProcessor.card_code_amount(:declined)
    @credit_card = credit_card('4000100011112224')
    @check = check
    @options = {
      order_id: '1',
      billing_address: address,
      description: 'Store Purchase',
      card_present_code: 'ManualKeyed'
    }
  end

  def test_successful_purchase
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_success response
    assert_equal 'Approved', response.message
    assert_match %r{Street address and postal code do not match}, response.avs_result["message"]
    assert_match %r{CVV matches}, response.cvv_result["message"]
  end

  def test_failed_purchase
    @amount = NullProcessor.card_code_amount(:declined)
    response = @gateway.purchase(@amount, @credit_card, @options)
    assert_failure response
    assert_equal 'Declined', response.message
  end

  def test_successful_purchase_with_echeck
    response = @gateway.purchase(@amount, @check, @options)
    assert_success response
    assert_equal 'Success', response.message
  end

  def test_successful_purchase_with_payment_account_token
    response = @gateway.store(@credit_card, @options)
    assert_success response

    response = @gateway.purchase(@amount, response.authorization, @options)
    assert_success response
    assert_equal 'Approved', response.message
  end

  def test_successful_purchase_with_shipping_address
    response = @gateway.purchase(@amount, @credit_card, @options.merge(shipping_address: address(address1: "Shipping")))
    assert_success response
    assert_equal 'Approved', response.message
  end

  def test_successful_authorize_and_capture
    auth = @gateway.authorize(@amount, @credit_card, @options)
    assert_success auth

    assert capture = @gateway.capture(@amount, auth.authorization)
    assert_success capture
    assert_equal 'Success', capture.message
  end

  def test_failed_authorize
    @amount = NullProcessor.card_code_amount(:declined)
    response = @gateway.authorize(@amount, @credit_card, @options)
    assert_failure response
    assert_equal 'Declined', response.message
  end

  def test_partial_capture
    auth = @gateway.authorize(@amount, @credit_card, @options)
    assert_success auth

    assert capture = @gateway.capture(@amount-1, auth.authorization)
    assert_success capture
  end

  def test_failed_capture
    response = @gateway.capture(@amount, '')
    assert_failure response
    assert_equal 'TransactionID required', response.message
  end

  def test_successful_refund
    purchase = @gateway.purchase(@amount, @credit_card, @options)
    assert_success purchase

    assert refund = @gateway.refund(@amount, purchase.authorization)
    assert_success refund
    assert_equal 'Approved', refund.message
  end

  def test_partial_refund
    purchase = @gateway.purchase(@amount, @credit_card, @options)
    assert_success purchase

    assert refund = @gateway.refund(@amount-1, purchase.authorization)
    assert_success refund
  end

  def test_failed_refund
    response = @gateway.refund(@amount, '')
    assert_failure response
    assert_equal 'TransactionID required', response.message
  end

  def test_successful_credit
    assert credit = @gateway.credit(@amount, @credit_card)
    assert_success credit
    assert_equal 'Approved', credit.message
  end

  def test_failed_credit
    response = @gateway.credit(@declined_amount, @credit_card)
    assert_failure response
    assert_equal 'Declined', response.message
  end

  def test_successful_void
    auth = @gateway.authorize(@amount, @credit_card, @options)
    assert_success auth

    assert void = @gateway.void(auth.authorization)
    assert_success void
    assert_equal 'Success', void.message
  end

  def test_failed_void
    response = @gateway.void('')
    assert_failure response
    assert_equal 'TransactionAmount required', response.message
  end

  def test_successful_verify
    response = @gateway.verify(@credit_card, @options)
    assert_success response
    assert_match %r{Success}, response.message

    response = @gateway.verify(@check, @options)
    assert_success response
    assert_match %r{Success}, response.message
  end

  def test_successful_store
    response = @gateway.store(@credit_card, @options)
    assert_success response
    assert_match %r{PaymentAccount created}, response.message
  end

  def test_invalid_login
    gateway = ElementGateway.new(account_id: '', account_token: '', application_id: '', acceptor_id: '', application_name: '', application_version: '')

    response = gateway.purchase(@amount, @credit_card, @options)
    assert_failure response
    assert_match %r{Invalid Request}, response.message
  end

  def test_transcript_scrubbing
    transcript = capture_transcript(@gateway) do
      @gateway.purchase(@amount, @credit_card, @options)
    end
    transcript = @gateway.scrub(transcript)

    assert_scrubbed(@credit_card.number, transcript)
    assert_scrubbed(@credit_card.verification_value, transcript)
    assert_scrubbed(@gateway.options[:account_token], transcript)
  end

  def test_transcript_scrubbing_with_echeck
    transcript = capture_transcript(@gateway) do
      @gateway.purchase(@amount, @check, @options)
    end
    transcript = @gateway.scrub(transcript)

    assert_scrubbed(@check.account_number, transcript)
    assert_scrubbed(@check.routing_number, transcript)
    assert_scrubbed(@gateway.options[:account_token], transcript)
  end

  def test_echeck_status
    response = @gateway.purchase(@amount, @check, @options)
    assert_success response
    assert_equal 'Success', response.message

    status_response = @gateway.query(response.authorization)
    assert_success status_response
    assert_equal 'Pending',status_response.query_items.first['transactionstatus']
    assert_equal '10',status_response.query_items.first['transactionstatuscode']
    assert_equal response.authorization.split("|").first, status_response.authorization
    # some other check on a status that has changed

  end
end
