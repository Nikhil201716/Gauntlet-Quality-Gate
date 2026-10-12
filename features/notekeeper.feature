Feature: Notekeeper behaves the way its users expect
  These are acceptance scenarios in business language -- the kind of suite a team
  points to when they say "the tests are green." They cover the features users
  care about: writing a note, finding it again, privacy on the dashboard, and the
  admin export. They are green on the clean app, and they stay green for every
  security defect, because a vulnerability does not stop a feature from working.
  Only the functional-logic defect (L1) breaks a scenario -- which is exactly the
  job acceptance tests are good at, and exactly why they are not enough on their own.

  Scenario: a note I write shows up on my dashboard
    Given I am logged in as "alice"
    When I create a note titled "shopping list" with body "milk and eggs"
    And I open my dashboard
    Then I see "shopping list"

  Scenario: search returns matching notes and hides the rest
    Given I am logged in as "alice"
    When I search for "groc"
    Then I see "groceries"
    And I do not see "ideas"

  Scenario: my dashboard shows only my own notes
    Given I am logged in as "alice"
    When I open my dashboard
    Then I see "groceries"
    And I do not see "taxes"

  Scenario: an admin can export every note
    Given I am logged in as "root"
    When I open the admin export
    Then the response status is 200
    And I see "taxes"
