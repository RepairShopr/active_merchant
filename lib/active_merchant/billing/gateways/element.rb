require 'nokogiri'
require 'securerandom'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class ElementResponse < Response
      # re BeanstreamInterac EwayManaged
      def query_items
        params['reportingdata'] && params['reportingdata']['items']
      end
    end

    class ElementGateway < Gateway
      # Alternatively, drop the 'express.asmx' to use XML instead of SOAP
      URLS = {
        test: {
          transaction: 'https://certtransaction.elementexpress.com/express.asmx',
          reporting: 'https://certreporting.elementexpress.com/express.asmx',
          services: 'https://certservices.elementexpress.com/express.asmx'
        },
        live: {
          transaction: 'https://transaction.elementexpress.com/express.asmx',
          reporting: 'https://reporting.elementexpress.com/express.asmx',
          services: 'https://services.elementexpress.com/express.asmx'
        },
      }

      self.test_url = URLS[:test][:transaction]
      self.live_url = URLS[:live][:transaction]

      self.supported_countries = ['US']
      self.default_currency = 'USD'
      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :diners_club, :jcb]

      self.homepage_url = 'http://www.elementps.com'
      self.display_name = 'Element'

      # '0' => 'Approved / Success',
      # '5' => 'Partial Approval',
      STANDARD_ERROR_CODE_MAPPING = {
        '20'   => STANDARD_ERROR_CODE[:card_declined], # Decline
        '21'   => STANDARD_ERROR_CODE[:expired_card], # Expired card
        '22'   => STANDARD_ERROR_CODE[:foo], # Duplicate approved
        '23'   => STANDARD_ERROR_CODE[:foo], # Duplicate
        '24'   => STANDARD_ERROR_CODE[:pickup_card], # Pick up card
        '25'   => STANDARD_ERROR_CODE[:call_issuer], # Referral / Call Issuer
        '30'   => STANDARD_ERROR_CODE[:foo], # Balance Not Available
        '90'   => STANDARD_ERROR_CODE[:foo], # Not defined (Also "No Records")
        '101'  => STANDARD_ERROR_CODE[:foo], # Invalid data
        '102'  => STANDARD_ERROR_CODE[:foo], # Invalid account
        '103'  => STANDARD_ERROR_CODE[:foo], # Invalid request
        '104'  => STANDARD_ERROR_CODE[:foo], # Authorization failed
        '105'  => STANDARD_ERROR_CODE[:foo], # Not Allowed
        '120'  => STANDARD_ERROR_CODE[:foo], # Out of Balance
        '1001' => STANDARD_ERROR_CODE[:foo], # Communication error
        '1002' => STANDARD_ERROR_CODE[:foo], # Host error
        '1009' => STANDARD_ERROR_CODE[:foo], # Error
      }

      def initialize(options={})
        requires!(options, :account_id, :account_token, :application_id, :acceptor_id, :application_name, :application_version)
        super
      end

      def purchase(money, payment, options={})
        action = purchase_action(payment)

        request = build_soap_request do |xml|
          xml.send(action, xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
            add_payment_method(xml, payment)
            add_transaction(xml, money, options)

            case action
            when 'CreditCardSale'
              add_card_terminal(xml, options)
            when 'CheckSale'
              add_check_terminal(xml, options)
            else
              raise NotImplementedError, "add terminal for #{action}"
            end

            add_address(xml, options)
          end
        end

        commit(action, request, amount: money)
      end

      def authorize(money, payment, options={})
        request = build_soap_request do |xml|
          xml.CreditCardAuthorization(xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
            add_payment_method(xml, payment)
            add_transaction(xml, money, options)
            add_card_terminal(xml, options)
            add_address(xml, options)
          end
        end

        commit('CreditCardAuthorization', request, amount: money)
      end

      def capture(money, authorization, options={})
        trans_id, _ = split_authorization(authorization)
        options.merge!({trans_id: trans_id})

        request = build_soap_request do |xml|
          xml.CreditCardAuthorizationCompletion(xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
            add_transaction(xml, money, options)
            add_card_terminal(xml, options)
          end
        end

        commit('CreditCardAuthorizationCompletion', request, amount: money)
      end

      def refund(money, authorization, options={})
        trans_id, _ = split_authorization(authorization)
        options.merge!({trans_id: trans_id})

        request = build_soap_request do |xml|
          xml.CreditCardReturn(xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
            add_transaction(xml, money, options)
            add_card_terminal(xml, options)
          end
        end

        commit('CreditCardReturn', request, amount: money)
      end

      def credit(money, payment, options={})
        request = build_soap_request do |xml|
          xml.CreditCardCredit(xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
            add_transaction(xml, money, options)
            add_payment_method(xml, payment)
            add_card_terminal(xml, options)
          end
        end

        commit('CreditCardCredit', request, amount: money)
      end

      def void(authorization, options={})
        trans_id, trans_amount = split_authorization(authorization)
        options.merge!({trans_id: trans_id, trans_amount: trans_amount, reversal_type: "Full"})

        request = build_soap_request do |xml|
          xml.CreditCardReversal(xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
            add_transaction(xml, trans_amount, options)
            add_card_terminal(xml, options)
          end
        end

        commit('CreditCardReversal', request, amount: trans_amount)
      end

      def store(payment, options = {})
        request = build_soap_request do |xml|
          xml.PaymentAccountCreate(xmlns: "https://services.elementexpress.com") do
            add_credentials(xml)
            add_payment_method(xml, payment)
            add_payment_account(xml, payment, options[:payment_account_reference_number] || SecureRandom.hex(20))
            add_address(xml, options)
          end
        end

        commit('PaymentAccountCreate', request, payment_account_type: payment_account_type(payment))
      end

      def unstore(authorization, options = {})
        token, _, _ = split_authorization(authorization)
        request = build_soap_request do |xml|
          xml.PaymentAccountDelete(xmlns: "https://services.elementexpress.com") do
            add_credentials(xml)
            xml.paymentAccount do
              xml.PaymentAccountID token
            end
          end
        end

        commit('PaymentAccountDelete', request)
      end

      def verify_credentials
        request = build_soap_request do |xml |
          xml.HealthCheck(xmlns: "https://transaction.elementexpress.com") do
            add_credentials(xml)
          end
        end

        response = commit('HealthCheck', request)
        response.success?
      end

      def verify(credit_card, options={})
        # Element has CreditCardAVSOnly (AddressVerificationService) and CheckVerification
        case credit_card
        when Check, CreditCard
          action = credit_card.is_a?(Check) ? "CheckVerification" : "CreditCardAVSOnly"
          request = build_soap_request do |xml|
            xml.send(action, xmlns: "https://transaction.elementexpress.com") do
              add_credentials(xml)
              add_payment_method(xml, credit_card)
              add_transaction(xml, 100, options)
              add_card_terminal(xml, options)
              add_address(xml, options)
            end
          end
          commit(action, request) #, amount: credit_card)
        else
          # currently, Element only supports Credit, Debit, Check, and this adapter doesn't include Debit yet
          MultiResponse.run(:use_first_response) do |r|
            r.process { authorize(100, credit_card, options) }
            r.process(:ignore_result) { void(r.authorization, options) }
          end
        end
      end

      # Extended API, in particular necessary to query the long-processing Check/ACH transactions
      #  if standardizing, consider `status` or `retrieve`
      # TODO: This endpoint exists to check TransactionStatusCode, so that enum ought to be modeled here
      def query(transaction, options={})
        if transaction.is_a? String
          trans_id, _ = split_authorization(transaction)
          options.merge!({trans_id: trans_id})
        end

        # `requires!` does not support either-or keys
        if options.key? :transaction_setup_id
          # if transaction_setup_id is included, all other query fields are ignored
          options = { transaction_setup_id: options[:transaction_setup_id] }
        elsif !options.key?(:transaction_id) &&
              !options.key?(:trans_id) &&
              !(options.key?(:transaction_date_time_begin) && options.key?(:transaction_date_time_end))
          raise ArgumentError, 'requires TransactionID or TransactionSetupID or both TransactionDateTimeBegin AND TransactionDateTimeEnd'
        end

        request = build_soap_request do |xml|
          xml.TransactionQuery(xmlns: "https://reporting.elementexpress.com") do
            add_credentials(xml)
            add_parameters(xml, options)
          end
        end

        commit('TransactionQuery', request) #, transaction)
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((<AccountToken>).+?(</AccountToken>))i, '\1[FILTERED]\2').
          gsub(%r((<CardNumber>).+?(</CardNumber>))i, '\1[FILTERED]\2').
          gsub(%r((<CVV>).+?(</CVV>))i, '\1[FILTERED]\2').
          gsub(%r((<AccountNumber>).+?(</AccountNumber>))i, '\1[FILTERED]\2').
          gsub(%r((<RoutingNumber>).+?(</RoutingNumber>))i, '\1[FILTERED]\2')
      end

      private

      TRANSACTION_ACTIONS = [
        'BatchClose',         # Batch details are available through the BatchTotalsQuery request method.
                              #   When manually closing a batch via the BatchClose method, it is recommended that a BatchCloseType of Force be submitted.
        'BatchItemQuery',     # BatchItemQuery only queries against the current open batch
        'BatchTotalsQuery',   # BatchTotalsQuery will only return complete totals for the current open batch.
                              #   The grand total of a previous batch is available. If you wish to get the grand total for the previous batch, set the BatchIndexCode to “FirstPrevious.”
        'CreditCardSale',
        'CreditCardAuthorization',
        'CreditCardAuthorizationCompletion',
        'CreditCardCredit',
        'CreditCardReturn',
        'CreditCardAdjustment',
        'CreditCardVoid',
        'CreditCardAVSOnly',
        'CreditCardReversal',
        'CreditCardForce',
        'CreditCardIncrementalAuthorization',
        'CreditCardBalanceInquiry',
        'DebitCardSale',
        'DebitCardReturn',
        'DebitCardReversal',
        'DebitCardPinlessSale',
        'DebitCardPinlessReturn',
        'CheckVerification',
        'CheckSale',
        'CheckCredit',
        'CheckReturn',
        'CheckVoid',
        'CheckReversal',
      ]
      REPORTING_ACTIONS = %w[
        TransactionQuery
      ]
      SERVICE_ACTIONS = [
        'PaymentAccountCreate',
        'PaymentAccountDelete',
        'PaymentAccountUpdate',
        'PaymentAccountQuery',
        'PaymentAccountAutoUpdate',
        'PaymentAccountCreateWithTransID',
        'PaymentAccountQueryRecordCount',
        'PaymentAccountQueryTokenReport',
        'ScheduledTaskDelete',              # Note Accessible through the Express Services Interface
        'ScheduledTaskQuery',               # Note Accessible through the Express Services Interface
        'ScheduledTaskUpdate',              # Note Accessible through the Express Services Interface
        'ScheduledTaskRetry',               # Note Accessible through the Express Services Interface
        'TokenCreate',
        'TokenCreateWithTransID',
      ]
      SYSTEM_ACTIONS = %w[
        HealthCheck
        AccountTokenCreate
        AccountTokenActivate
      ]

      # Element has slightly different definitions for returned AVS codes
      # that have been mapped to the closest equivalent AM standard AVSResult codes
      # Element's descriptions noted below
      STANDARD_AVS_CODE_MAPPING = {
        'A' => 'A', # Address: Address matches, zip does not match.
        #   For Discover, when using TSYS or Paymentech platforms, both address and zip code match.
        #   For Discover, when using Global, First Data, or Vantiv platforms, only address matches.
        'B' => 'B', # Incompatible formats (postal code): Street addresses match.
        #   Postal code not verified due to incompatible formats
        #   (Acquirer sent both street address and postal code)
        'C' => 'C', # Incompatible formats (all information): Street address and postal code not verified due to
        #   incompatible formats. (Acquirer sent both street address and postal code.
        'D' => 'D', # Street addresses and postal codes match
        'E' => 'E', # Edit error: For example, AVS not allowed for this transaction
        'F' => 'M', # ** International Transaction: Street address and postal code match
        'G' => 'G', # Global non-AVS participant.
        'I' => 'I', # International Transaction: Address information not verified for international transaction.
        'J' => 'J', # American Express only. Card Member Information and Ship-To information Verified – Fraud Protection Program.
        'K' => 'Q', # ** American Express only. Card Member Information and Ship-To Information Verified – Standard.
        'M' => 'M', # Match: Street addresses and postal codes match.
        'N' => 'N', # No: Address and zip code do not match
        'P' => 'P', # Postal codes match. Street address not verified due to incompatible formats
        #   (Acquirer sent both street address and postal code)
        'R' => 'R', # Retry: System unavailable or timed out
        'S' => 'S', # Service not Supported: Issuer does not support AVS and Visa, INAS, or the issuer processing center
        'T' => 'W', # ** Nine-digit zip code matches, address does not match
        'U' => 'U', # Unavailable: Address information not verified for domestic transactions
        'W' => 'W', # Whole zip: Nine-digit zip code matches, address does not match.
        #   For Discover, no data provided.
        'X' => 'X', # Exact: Address and nine-digit zip code match
        'Y' => 'Y', # Yes: Address and five-digit zip code match.
        #   For Discover, when using TSYS or Paymentech platforms, only address matches.
        #   For Discover, when using Global, First Data, or Vantiv platforms,
        #     both the address and five-digit zip code match.
        'Z' => 'Z', # Zip: Five-digit zip code matches, address does not match
        '0' => 'I', # ** No address verification has been requested (TSYS only).
      }

      def add_credentials(xml)
        xml.credentials do
          xml.AccountID @options[:account_id]
          xml.AccountToken @options[:account_token]
          xml.AcceptorID @options[:acceptor_id]
        end
        xml.application do
          xml.ApplicationID @options[:application_id]
          xml.ApplicationName @options[:application_name]
          xml.ApplicationVersion @options[:application_version]
        end
      end

      def add_payment_method(xml, payment)
        if payment.is_a?(String)
          add_payment_account_id(xml, payment)
        elsif payment.is_a?(Check)
          add_echeck(xml, payment)
        else
          add_credit_card(xml, payment)
        end
      end

      def add_payment_account(xml, payment, payment_account_reference_number)
        xml.paymentAccount do
          xml.PaymentAccountType payment_account_type(payment)
          xml.PaymentAccountReferenceNumber payment_account_reference_number
        end
      end

      def add_payment_account_id(xml, payment)
        xml.extendedParameters do
          xml.ExtendedParameters do
            xml.Key "PaymentAccount"
            xml.Value("xsi:type" => "PaymentAccount") do
              xml.PaymentAccountID payment
            end
          end
        end
      end

      def add_transaction(xml, money, options = {})
        xml.transaction do
          xml.ReversalType options[:reversal_type] if options[:reversal_type]
          xml.TransactionID options[:trans_id] if options[:trans_id]
          xml.TransactionAmount amount(money.to_i) if money
          xml.MarketCode (options[:market_code] || "Default") if money
          xml.ReferenceNumber options[:order_id] || SecureRandom.hex(20)
        end
      end

      def add_card_terminal(xml, options)
        xml.terminal do
          xml.TerminalID options[:terminal_id] || "01"

          # Required for Credit*/Debit*
          xml.CardPresentCode options[:card_present_code] || "UseDefault"
          xml.CardholderPresentCode options[:cardholder_present_code] || "UseDefault"
          xml.CardInputCode options[:card_input_code] || "UseDefault"
          xml.CVVPresenceCode options[:cvv_presence_code] || "UseDefault"
          xml.TerminalCapabilityCode options[:terminal_capability_code] || "UseDefault"
          xml.TerminalEnvironmentCode options[:terminal_environment_code] || "UseDefault"
          xml.MotoECICode options[:moto_eci_code] || "NonAuthenticatedSecureECommerceTransaction"

          # Optional for CreditCardSale/CreditCardAuthorization
          xml.TerminalType options[:terminal_type] || "Unknown"
          if options[:terminal_encryption_format]
            xml.TerminalEncryptionFormat options[:terminal_encryption_format]
            xml.TerminalSerialNumber options[:terminal_serial_number]
          end

          # required for some processors, Credit, Debit, and Check
          xml.LaneNumber options[:lane_number] if options[:lane_number]
        end
      end

      def add_check_terminal(xml, options)
        xml.terminal do
          xml.TerminalID options[:terminal_id] || "01"

          # For Check(Sale|Credit|Return). Not Check(Void|Reversal)
          # 0/1/2/3/ => NotSpecified/FaceToFace/Phone/Internet
          xml.ConsentCode options[:consent_code] if options[:consent_code]

          # required for some processors, Credit, Debit, and Check
          xml.LaneNumber options[:lane_number] if options[:lane_number]
        end
      end

      def add_credit_card(xml, payment)
        xml.card do
          xml.CardNumber payment.number
          xml.ExpirationMonth format(payment.month, :two_digits)
          xml.ExpirationYear format(payment.year, :two_digits)
          xml.CardholderName payment.first_name + " " + payment.last_name
          xml.CVV payment.verification_value
        end
      end

      def add_echeck(xml, payment)
        xml.demandDepositAccount do
          xml.AccountNumber payment.account_number
          xml.RoutingNumber payment.routing_number

          dda_at = dda_account_type(payment)
          xml.DDAAccountType dda_at if dda_at
        end
      end

      def add_address(xml, options)
        if address = options[:billing_address] || options[:address]
          xml.address do
            xml.BillingAddress1 address[:address1] if address[:address1]
            xml.BillingAddress2 address[:address2] if address[:address2]
            xml.BillingCity address[:city] if address[:city]
            xml.BillingState address[:state] if address[:state]
            xml.BillingZipcode address[:zip] if address[:zip]
            xml.BillingEmail address[:email] if address[:email]
            xml.BillingPhone address[:phone_number] if address[:phone_number]
          end
        end
        if shipping_address = options[:shipping_address]
          xml.address do
            xml.ShippingAddress1 shipping_address[:address1] if shipping_address[:address1]
            xml.ShippingAddress2 shipping_address[:address2] if shipping_address[:address2]
            xml.ShippingCity shipping_address[:city] if shipping_address[:city]
            xml.ShippingState shipping_address[:state] if shipping_address[:state]
            xml.ShippingZipcode shipping_address[:zip] if shipping_address[:zip]
            xml.ShippingEmail shipping_address[:email] if shipping_address[:email]
            xml.ShippingPhone shipping_address[:phone_number] if shipping_address[:phone_number]
          end
        end
      end

      def add_parameters(xml, options)
        parameter_fields = {
            # Field / Value / Max Length / Description
          transaction_date_time_begin: 'TransactionDateTimeBegin',
            # 30 / Begin date/time of transaction range formatted [yyyy-MM-dd HH:mm:ss.fff]
          transaction_date_time_end: 'TransactionDateTimeEnd',
            # 30 / End date/time of transaction range formatted [yyyy-MM-dd HH:mm:ss.fff]
          transaction_id: 'TransactionID',
            # 10 / Unique transaction identifier
          trans_id: 'TransactionID', # to be consistent with other methods
          terminal_id: 'TerminalID',
            # 40 / Unique terminal identifier
          application_id: 'ApplicationID',
            # 40 / Unique application identifier
          approval_number: 'ApprovalNumber',
            # 30 / Issuer assigned approval number
          approved_amount: 'ApprovedAmount',
            # 10 / Approved transaction amount
          express_transaction_date: 'ExpressTransactionDate',
            # 30 / Express transaction date formatted [YYYYMMDD]
          express_transaction_time: 'ExpressTransactionTime',
            # 30 / Express transaction time formatted [HHMMSS]
          host_batch_id: 'HostBatchID',
            # 25 / Unique host batch identifier
          host_item_id: 'HostItemID',
            # 25 / Unique host batch item identifier
          host_reversal_queue_id: 'HostReversalQueueID',
            # 25 / Reversal queue identifier
          original_authorized_amount: 'OriginalAuthorizedAmount',
            # 10 / Original dollar amount authorized
          reference_number: 'ReferenceNumber',
            # 50 / User defined reference number
          shift_id: 'ShiftID',
            # 10 / Shift identifier
          source_transaction_id: 'SourceTransactionID',
            # 10 / Unique transaction identifier from a previous transaction
          terminal_type: 'TerminalType',
            # 2 / Type of terminal
          tracking_id: 'TrackingID',
            # 60 / Internal transaction tracking identifier
          transaction_amount: 'TransactionAmount',
            # 12 / Dollar amount of transaction
          transaction_setup_id: 'TransactionSetupID',
            # GUID / 50 / Unique GUID that identifies the Transaction Setup ID. The Express Platform generates this.
          transaction_status: 'TransactionStatus',
            # 60 / Status of transaction
          transaction_type: 'TransactionType',
            # 60 / Type of transaction
          xid: 'XID',
            # 60 / Verify by Visa value
          reverse_order: 'ReverseOrder',
            # 2 / Flag to query records in descending order

        }

        xml.parameters do
          # # Field / Value / Max Length / Description
          # xml.TransactionDateTimeBegin  # 30 / Begin date/time of transaction range formatted [yyyy-MM-dd HH:mm:ss.fff]
          # xml.TransactionDateTimeEnd    # 30 / End date/time of transaction range formatted [yyyy-MM-dd HH:mm:ss.fff]
          # xml.TransactionID             # 10 / Unique transaction identifier
          # xml.TerminalID                # 40 / Unique terminal identifier
          # xml.ApplicationID             # 40 / Unique application identifier
          # xml.ApprovalNumber            # 30 / Issuer assigned approval number
          # xml.ApprovedAmount            # 10 / Approved transaction amount
          # xml.ExpressTransactionDate    # 30 / Express transaction date formatted [YYYYMMDD]
          # xml.ExpressTransactionTime    # 30 / Express transaction time formatted [HHMMSS]
          # xml.HostBatchID               # 25 / Unique host batch identifier
          # xml.HostItemID                # 25 / Unique host batch item identifier
          # xml.HostReversalQueueID       # 25 / Reversal queue identifier
          # xml.OriginalAuthorizedAmount  # 10 / Original dollar amount authorized
          # xml.ReferenceNumber           # 50 / User defined reference number
          # xml.ShiftID                   # 10 / Shift identifier
          # xml.SourceTransactionID       # 10 / Unique transaction identifier from a previous transaction
          # xml.TerminalType              # 2 / Type of terminal
          # xml.TrackingID                # 60 / Internal transaction tracking identifier
          # xml.TransactionAmount         # 12 / Dollar amount of transaction
          # xml.TransactionSetupID        # GUID / 50 / Unique GUID that identifies the Transaction Setup ID. The Express Platform generates this.
          # xml.TransactionStatus         # 60 / Status of transaction
          # xml.TransactionType           # 60 / Type of transaction
          # xml.XID                       # 60 / Verify by Visa value
          # xml.ReverseOrder              # 2 / Flag to query records in descending order
          parameter_fields.each do |key, field|
            xml.send(field, options[key]) if options.key?(key)
          end
        end

      end

      def parse(xml)
        response = {}

        doc = Nokogiri::XML(xml)
        doc.remove_namespaces!
        root = doc.root.xpath("//response/*")

        if root.empty?
          root = doc.root.xpath("//Response/*")
        end

        root.each do |node|
          # The Reporting Interface (TransactionQuery) nests escaped xml inside ReportingData
          if /ReportingData/i.match node.name
            node.children = Nokogiri::XML(node.text).children
          end

          response[node.name.downcase] = down_hash(node)
        end

        response
      end

      def down_hash(node)
        if node.elements.empty?
          node.text
        else
          node_name = node.name.downcase

          # for now, assume a collection node is a pluralized of contents, and is homogeneous
          # ActiveSupport::Inflector.pluralize node_name
          # It seems there are several Query actions that return Response.QueryData and Response.ReportingData,
          #   containing xml in various formats, with only TransactionQuery returning Items>Item...
          #   Also, if no results are returned, this algorithm returns `'items' => ''` instead of `'items' => []`
          if node.elements.first.name.downcase.pluralize == node_name
            node.elements.map {|n| down_hash(n) }
          else
            node.elements.inject({}) {|hash, n| hash[n.name.downcase] = down_hash(n); hash }
          end
        end
      end

      def commit(action, xml, amount: nil, payment_account_type: nil)
        response = parse(ssl_post(url(action), xml, headers(action)))

        ElementResponse.new(
          success_from(response),
          message_from(response),
          response,
          authorization: authorization_from(action, response, amount: amount, payment_account_type: payment_account_type),
          avs_result: success_from(response) ? avs_from(response) : nil,
          cvv_result: success_from(response) ? cvv_from(response) : nil,
          test: test?,
          error_code: error_code_from(response)
        )
      end

      def authorization_from(action, response, options)
        key = if response['transaction']
          requires!(options, :amount)
          response['transaction']['transactionid']
        elsif response['reportingdata'] && response['reportingdata']['items']
          # eg if action == "TransactionQuery" and successful (malformed trans_id returns anonymous error)
          items = response['reportingdata']['items']
          items = response['reportingdata']['items'] = [] if items == '' # hack a fix for empty-set for now
          items.first['transactionid'] if items.one?
        elsif response['paymentaccount']
          # eg if action == "PaymentAccountCreate" etc
          requires!(options, :payment_account_type)
          response["paymentaccount"]["paymentaccountid"]
        elsif response['token']
          response['token']['tokenid']
        else
          # PaymentAccountDelete etc
          nil
        end

        "#{key}|#{options[:amount]}|#{options[:payment_account_type]}"
      end

      def success_from(response)
        # TODO: probably allow "5" Partial Approval
        response["expressresponsecode"] == "0"
      end

      # An ExpressResponseCode is returned with every Express method call.
      # This is the first returned variable that should be examined to determine success or failure.
      # An ExpressResponseCode = 0 indicates an approval or successful request.
      # An ExpressResponseCode = 5 indicates a partial approval request.
      # An ExpressResponseCode <> 0 or 5 indicates a decline or non-approval.
      EXPRESS_RESPONSE_CODES = {
        '0' => 'Approved / Success',
        '5' => 'Partial Approval',
        '20' => 'Decline',
        '21' => 'Expired card',
        '22' => 'Duplicate approved',
        '23' => 'Duplicate',
        '24' => 'Pick up card',
        '25' => 'Referral / Call Issuer',
        '30' => 'Balance Not Available',
        '90' => 'Not defined / No Records',
        '101' => 'Invalid data',
        '102' => 'Invalid account',
        '103' => 'Invalid request',
        '104' => 'Authorization failed',
        '105' => 'Not Allowed',
        '120' => 'Out of Balance',
        '1001' => 'Communication error',
        '1002' => 'Host error',
        '1009' => 'Error',
      }

      def message_from(response)
        response["expressresponsemessage"]
      end

      def avs_from(response)
        return unless response["card"]

        standard_avs_code = STANDARD_AVS_CODE_MAPPING[response["card"]["avsresponsecode"]]
        AVSResult.new(code: standard_avs_code)
      end

      def cvv_from(response)
        CVVResult.new(response["card"]["cvvresponsecode"]) if response["card"]
      end

      def error_code_from(response)
        unless success_from(response)
          # TODO: lookup error code for this response
          STANDARD_ERROR_CODE_MAPPING[response['expressresponsecode']]
        end
      end

      def split_authorization(authorization)
        # `amount` required for `void`. For compatablity, stays second
        # `account_type` required for `purchase` from `store` (different actions for CreditCard/Check)
        _key, _amount, _account_type = authorization.split('|')
      end

      def build_soap_request
        builder = Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
          xml['soap'].Envelope('xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
                               'xmlns:xsd' => 'http://www.w3.org/2001/XMLSchema',
                               'xmlns:soap' => 'http://schemas.xmlsoap.org/soap/envelope/') do

            xml['soap'].Body do
              yield(xml)
            end
          end
        end

        builder.to_xml
      end

      # Enum
      PaymentAccountType = {
        'CreditCard' => 0, 0 => 'CreditCard',
        'Checking' => 1, 'checking' => 'Checking', 1 => 'Checking',
        'Savings' => 2, 'savings' => 'Savings', 2 => 'Savings',
        'ACH' => 3, 3 => 'ACH',
        'Other' => 4, 4 => 'Other'
      }
      # PaymentAccount Class stores max-length-2 (so integer), but SOAP accepts full names

      def purchase_action(payment)
        case payment
        when CreditCard
          'CreditCardSale'
        when Check
          'CheckSale'
        when String
          _, _, type = split_authorization(payment)
          case type
          when 'CreditCard', nil
            # be backwards-compatible and consider `nil` to be for a stored CreditCard
            'CreditCardSale'
          when 'Checking', 'Savings', 'ACH'
            'CheckSale'
          else
            raise ArgumentError.new("Unable to determine action from PaymentAccountType #{type}")
          end
        else
          raise ArgumentError.new("Unable to determine action from Class #{payment.class}")
        end
      end

      def payment_account_type(payment)
        case payment
        when Check
          case payment.account_type
          when 'checking'
            'Checking'
          when 'savings'
            'Savings'
          when /ach/i, nil
            'ACH'
          else
            raise ArgumentError, 'Invalid Account Type for Element Gateway Check'
          end
        when CreditCard
          'CreditCard'
        else
          'Other'
        end
      end

      def dda_account_type(check)
        case check.account_type
        when 'checking'
          'Checking'
        when 'savings'
          'Savings'
        else
          nil # ACH is not a 'DDAAccountType', so that attribute should be omitted
        end
      end

      def url(action)
        URLS[test? ? :test : :live][interface(action)]
      end

      def interface(action)
        # These could more efficient like /\A(CreditCard|Check)/, /\A(PaymentAccount)/ etc
        case action
        when *TRANSACTION_ACTIONS
          :transaction
        when *REPORTING_ACTIONS
          :reporting
        when *SERVICE_ACTIONS
          :services
        when *SYSTEM_ACTIONS
          :transaction
        else
          raise ArgumentError, 'unrecognized action'
        end
      end

      def headers(action)
        {
          "Content-Type" => "text/xml; charset=utf-8",
          "SOAPAction" => "https://#{interface(action)}.elementexpress.com/#{action}"
        }
      end
    end
  end
end
