Feature: Continuous Access Evaluation (CAEP) Session Revocation over SSF

  As an enterprise security administrator
  I want to propagate session revocation events via Shared Signals Framework (SSF)
  So that compromised user sessions are terminated instantly across all gateway endpoints

  Scenario: Ingesting a valid session-revoked event blocks subsequent API access
    Given the Sentinel gateway and Keycloak are healthy and online
    And a corporate officer is authenticated with session ID "ssf-session-999"
    And they present a valid DPoP proof matching their certificate
    When they attempt to access their secure profile
    Then the API gateway must allow the request with a "200 OK" status
    When the identity provider sends a backchannel "session-revoked" SSF event for session ID "ssf-session-999"
    Then the SSF receiver must accept the event with a "202 Accepted" status
    When they attempt to access their secure profile again with the same session
    Then the API gateway must reject the request with a "401 Unauthorized" status
    And the response error must specify "Session has been terminated."
