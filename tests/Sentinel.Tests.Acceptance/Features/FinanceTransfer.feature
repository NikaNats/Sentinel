Feature: High-Value Financial Wire Transfer under FAPI 2.0 Constraints

  As an authorized corporate officer
  I want to execute a high-value financial transfer
  So that funds are securely moved to a destination account only within my cryptographically signed bounds

  Scenario: Attempting high-value transfer with weak MFA level must trigger step-up challenge
    Given the Sentinel gateway and Keycloak are healthy and online
    And the corporate officer is authenticated with security level "acr2"
    When they attempt to transfer 50000 "USD" to account "acc-9988"
    Then the API gateway must reject the request with a "401 Unauthorized" status
    And the response must contain a step-up challenge requiring "acr3"

  Scenario: Executing transfer within signed Rich Authorization Request (RAR) bounds succeeds
    Given the corporate officer has completed "acr3" hardware MFA
    And their token authorizes a transfer of up to 50000 "USD" with transaction ID "txn-100"
    And they present a valid DPoP proof matching their certificate
    When they request to transfer 50000 "USD" with transaction ID "txn-100" to "acc-9988"
    Then the API gateway must approve the transfer with a "200 OK" status
    And the response transaction status must be "Approved"

  Scenario: Transfer exceeding signed Rich Authorization Request (RAR) bounds is blocked
    Given the corporate officer has completed "acr3" hardware MFA
    And their token authorizes a transfer of up to 50000 "USD" with transaction ID "txn-100"
    And they present a valid DPoP proof matching their certificate
    When they attempt to transfer 100000 "USD" with transaction ID "txn-100" to "acc-9988"
    Then the API gateway must block the transfer with a "403 Forbidden" status
    And the response error must specify "Authorization Bounds Exceeded"
