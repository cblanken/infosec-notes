# Active Directory (AD)
*Active Directory* (AD) is the directory service for Windows Domain Networks. AD allows for control and monitoring of all a companies users through a single *domain controller*. It allows a single user to sign into any computer on the AD network.

- Domain Controller: holds the `AD DS data store` and allows admin access to domain resources.
- AD DS (Domain Services) Data Store
    - `NTDS.dit`: a database of all the AD domain controller info such as password hashes for domain users. By default the `NTDS.dit` is stored in `%SystemRoot%\NTDS` and only accessible by the domain controller.
- Forests, Trees, Domains
    - Forest: a collection of one or more domain trees in an AD network
    - Trees - A hierarchy of domains in Active Directory Domain Services
    - Domains - Used to group and manage objects 
    - Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
    - Trusts - Allows users to access resources in other domains
    - Objects - users, groups, printers, computers, shares
    - Domain Services - DNS Server, LLMNR, IPv6
    - Domain Schema - Rules for object creation
- Users
    - Domain Admins: the big boss, only ones with access to the domain controller.
    - Service Accounts (can also be Domain Admins) these mostly aren't used except for service maintenance.
    - Local Admins: these users can make changes on local machines as admin but __cannot__ access the domain controller.
    - Domain users: everyday users, may have local admin to machines to machinens they have access to. 
- Groups
    - Security Groups: these groups can specify permissions for many users
    - Default Security Groups
	- Domain Controllers: all domain controllers in the domain
	- Domain Guests: all domain guests
	- Domain User: all domain users
	- Domain Computers: all workstations and servers joined to the domain
	- Domain Admins: designated admins of the domain
	- Enterprise Admins: designated admins of the enterprise
	- Schema Admins: designated admins of the schema
	- DNS Admins: 
	- DNS Update Proxy: DNS clients who are permitted to perform dynamic updates on behalf of some othe rclients (such as DHCP servers)
	- Allowed RODC Password Replication Group: members can have their passwords replicated to all read-only domain ccontrollers in the domain
	- Group Policy Creator Owners: members can modify group policy for the domain
	- Denied RODC Password Replication Group: members cannot have their passwords replicated to any read-only domain controllers in the domain
	- Protected users: members are affored additional protections against authentication security threats.
	- Cert Publishers: members are permitted to publish certificates to the directory
	- Enterprise Read-Only Domain Controllers: members ccan perform admin actions on key objects within the forest
	- Cloneable Domain Controllers: members that are domain controllers can be cloned
	- RAS and IAS Servers: servers in this group can access remote access properties of users
    - Distribution Groups: these groups can specify email distribution lists.
- Trusts: a mechanism for users in the network to gain access to other resources in the domain. Mostly truts outline the way domains inside a forest communicate with each other.
    - Directional Trusts: the direction of the trust flows from a *trusting* domain to a *trusted* domain
    - Transitive: the trust relationship expands beyond just two domains to include to include other trusted domains	
- Policies: dictate how the server operates and what rules it will or won't follow. These rules apply to the entire domain.
- Domain Services + Auth
    - *Domain Services* are just services the domain controller provides to the rest of the domain or tree.
    - Default Domain Services
	- LDAP (Lightweigth Directory Access Protocol): provides communication between applications and directory services
	- Certificate Services: allows the domain controller to create, validate and revoke public key certificates
	- DNS, LLMNR, NBT-NS: domain name services for identifying IP hostnames
	- Authentication: The most important and vulnerable part of AD. Two type: NTLM and Kerberos. 
	    - NTLM: default Windows auth protocol uses an encrypted challenge/response
	    - Kerberos: default auth service for AD, uses ticket-granting tickets and service tickets to authenticate users
- Azure (AD in the Cloud)
	|Windows Server AD|Azure AD
	|---|---
	|LDAP|Rest APIs
	|NTLM|OAuth/SAML
	|Kerberos|OpenID
	|OU Tree|Flat Structure
	|Domains and Forests|Tenants
	|Trusts|Guests

