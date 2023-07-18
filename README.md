# Net::LDAP::Simple

_NOTE: name is a placeholder_

## SYNOPSIS

    my $ldap = Net::LDAP::Simple->new();

    $ldap->add_role(editors => [qw(FOOAccess editors)]);

    if ($ldap->is_role(user => 'bob', role => 'editors')) {
        # YAY they have access
    } else {
        # UH OH, no access for this person
    }

## DESCRIPTION

This module provides a, hopefully, simple interface to an Active Directory
LDAP structure to make authorization decisions based on group, aka role,
membership.

Roles are defined with a custom name for the role with the value being an
arrayref of the ldap search path from left to right where the last element is
the end of the ldap tree. For example the **FOO** application has a role to
grant only specific users the ability to edit documents. The ldap path for
that role is `OU=editors,CN=FOOAccess,CN=Groups,DC=example,DC=com`.
All searches are rooted in the ldap path `CN=Groups,DC=example,DC=com`.
This leaves us with just `OU=editors,CN=FOOAccess` to define as the role to
search. We can set the search path for a new role as the following:

        $ldap->add_role(foo_editors => [qw(FOOAccess editors)]);

The search path need only be a single OU deep, or can be as deep as the ldap
tree goes. For instance, assume the HR tree in ActiveDirectory has no
groups/roles so to define that role we just need:

        $ldap->add_role(hr => ['HR']);

## ENVIRONMENT Variables

To run unit tests for this module the following environment variables are required:

* **LDAP_HOST** - Hostname running ActiveDirectory.
* **LDAP_BINDDN** - The username to *bind* as to ActiveDirectory LDAP connection.
* **LDAP_BINDPW** - The password to the *binddn* user.

The following environment variables are optional and trigger different tests:

* **USER** - A real username that exists in ActiveDirectory *(typically your logged in username)*
* **LDAP_PASSWORD** - The ActiveDirectory password for **USER**
* **TEST_LDAP_USER** - A boolean variable that controls whether or not to test the real **USER** against ActiveDirectory.
* **TEST_LDAP_PASSWORD** - A boolean variable that will cause the test to prompt for the **USER** password instead of using the **LDAP_PASSWORD** variable
* **TEST_AD_TIMEOUT** - A boolean variable to run the ActiveDirectory connection timeout tests *(causes the test to sleep for 30 minutes)*
