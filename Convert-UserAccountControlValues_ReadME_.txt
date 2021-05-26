Simply as a proof-of-concept, I have modified the script from https://gallery.technet.microsoft.com/Convert-userAccountControl-629eed01 to search for accounts that are configured for settings such as:

•	Unconstrained Delegation
•	Constrained Delegation (S4U2S)
•	Password Never Expires
•	Store Pwd Using Reversible Encryption
•	Account is Sensitive and Cannot Be Delegated (this is a good setting for any privileged account)
•	Use Only Kerberos DES Encryption Types for This Account
•	Do Not Require Kerberos PreAuthentication

Rename extension to ps1. Does not require any elevated privileges.

THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
