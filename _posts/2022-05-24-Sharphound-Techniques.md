---
title: Sharphound Techniques
published: true
---


Sharphound is a collection tool that is mainly used by the famous tool Bloodhound for gathering data from Active Directory environment. This post is about ways to catch sharphound on the network. Why bother catching sharphound on the network when signature based detection is easiest way to detect them? Detecting on network layer purely looks at the technique / behavior itself. Changing few lines or function name changes the hash of the executable, but it does not change the network behavior. 

With that being said, network behavior is not bullet proof either. There are different techniques that can achieve the same goal. I will list them out under each techniques to further enhance defense strategies. 

* If you want pcaps, shoot me an email via soso-security@protonmail.com


## Collection Methods
Below list is available collection methods on sharphound
-	  Container - Performs container collection
-     Group - Performs group membership collection
-     LocalGroup - Performs local group collection (DCOM \| RDP \| LocalAdmin \| PSRemote)
-     GPOLocalGroup - Collects OU objects to grab objects with gplink attribute
-     ComputerOnly - Enumerates Computers in Domain (Computer Enumeration \| LocalGroup \| Session Enumeration)
-     RDP - Performs Remote Desktop Users collection
-     DCOM - Performs Distributed COM Users collection
-     DCOnly - Runs all collection methods that can be queried from the DC only, no connection to member hosts/servers needed. (ACL \| Container \| Group \| ObjectProps \| Trusts \| GPOLocalGroup)
-     Session - Performs session collection
-     Acl - Performs ACL collection
-     Trusts - Performs domain trust enumeration
-     LoggedOn - Performs privileged Session enumeration (requires local admin on the target)
-     ObjectProps - Performs Object Properties collection for many AD objects 
-     SPNTargets - Performs SPN enumeration

## Techniques
From Collection methods, I've narrowed down to

**LDAP**
- [Container Enumeration](#container-enumeration)
- [Group Enumeration](#group-enumeration)
- [GPO Enumeration](#gpo-enumeration)
- [Computer Enumeration](#computer-enumeration)
- [SPN Enumeration](#spn-enumeration)
- [Trusts Enumeration](#trust-enumeration)
- [User Enumeration](#user-enumeration)
- [Ideas](#ideas)

**DCERPC**
- [Local Admin \| PS Remote \| RDP \| DCOM](#local-admin--ps-remote--rdp--dcom)
- [Session Enumeration](#session-enumeration)
- [LoggedOn User Enumeration](#loggedon-user-enumeration)
- [Ideas](#ideas-1)

---

# LDAP Techniques


## Container Enumeration 

Container enumeration grabs all containers of AD tree. Easier way of defining "Container" is "Folder" where AD objects reside. For example, here is one entry from container enumeration

`CN=Users,DC=f1,DC=ad,DC=lab,DC=ch`

Inside Users container, all Domain User objects reside 
Enumeration of Containers allows attackers to map out the structure of the AD tree without enumerating all objects in the tree.

### Simulation

**Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | Filter |
|---|---|---|
| 503 | 2022-05-10-sharphound_container.pcap | `(objectClass=container)"` |


### Alternate Attack Vectors
This can be used by both red teams and blue teams

`(ObjectCategory=container)`

---

## Group Enumeration

Group enumeration grabs all group objects from the domain. 

```
  (|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))
```

 https://github.com/BloodHoundAD/SharpHoundCommon/blob/d402833198a249f1aab7c8ca4ac47965807290ef/src/CommonLib/LDAPQueries/LDAPFilter.cs#L79

 Identifying different groups in the domain can allow the attacker to later enumerate users in a specific group.


### Simulation

 
 **Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame# | Pcap | Filter |
|---|---|---|
| 878 | 2022-05-10-sharphound_group.pcap | `(|(|(|(|(samaccounttype=268435456)(samaccounttype=268435457))(samaccounttype=536870912))(samaccounttype=536870913))(primarygroupid=*))` |


https://github.com/BloodHoundAD/SharpHoundCommon/blob/d402833198a249f1aab7c8ca4ac47965807290ef/src/CommonLib/LDAPQueries/LDAPFilter.cs#L79

268435456 - SAM_GROUP_OBJECT

268435457 - SAM_NON_SECURITY_GROUP_OBJECT

536870912 - SAM_ALIAS_OBJECT

536870913 - SAM_NON_SECURITY_ALIAS_OBJECT

Sharphound by default adds Primary Group ID filter when Group collection method is used 
```
		 if ((methods & ResolvedCollectionMethod.Group) != 0)
		{
			query = query.AddGroups().AddPrimaryGroups();
			props.AddRange(CommonProperties.GroupResolutionProps);
		}
				
```
https://github.com/BloodHoundAD/SharpHound/blob/af71c15e303a967ecf57808376165a4371809219/src/Producers/BaseProducer.cs#L80
 
 [AddPrimaryGroups](https://github.com/BloodHoundAD/SharpHoundCommon/blob/d402833198a249f1aab7c8ca4ac47965807290ef/src/CommonLib/LDAPQueries/LDAPFilter.cs#L92) function adds the query

 `(primarygroupid=*)`

 making final group collection query look like 

 ```
(|(|(|(|(samaccounttype=268435456)(samaccounttype=268435457))(samaccounttype=536870912))(samaccounttype=536870913))(primarygroupid=*))
```
 
 
### Alternate Attack Vectors

| Description | Filter |
|---|---|
| get all groups | `(objectClass=group)` |
| get all groups | `(objectCategory=group)` |
| get all groups | `(grouptype=*)` |
| get all primary groups |  `(primarygroupid=*)` |
| All distribution groups |	`(&(objectCategory=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))` |
| All security groups | `(groupType:1.2.840.113556.1.4.803:=2147483648)` |
| All built-in groups | `(groupType:1.2.840.113556.1.4.803:=1)` |
| All global groups |	`(groupType:1.2.840.113556.1.4.803:=2)` |
| All domain local groups |	`(groupType:1.2.840.113556.1.4.803:=4)` |
| All universal groups |	`(groupType:1.2.840.113556.1.4.803:=8)` |
| All global security groups | `(groupType=-2147483646)` |
| All universal security groups |	`(groupType=-2147483640)` |
| All domain local security groups | `(groupType=-2147483644)` |
| All global distribution groups |	`(groupType=2)` |
| Domain Admins group |  `(primarygroupid=512)` |
| Domain Users group |  `(primarygroupid=513)` |
| Domain Computers group | `(primaryGroupID=515)`|

---

## GPO Enumeration

GPOLocalGroup collection, unlike the name suggests, is not enumerating local groups, rather it enumerates all **OU** objects and grabs its **GPLink** attribute which maps to LDAP path of the GPOs that are linked to the container.

There is another technique in Sharphound [AddGPOs](https://github.com/BloodHoundAD/SharpHoundCommon/blob/d402833198a249f1aab7c8ca4ac47965807290ef/src/CommonLib/LDAPQueries/LDAPFilter.cs#L104) that grabs all Group Policy Objects

`(&(objectcategory=groupPolicyContainer)(flags=*))`



### Simulation 
 
 **Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | Filter |
|---|---|---|
| 505 | 2022-05-10-sharphound_GPOLocalgroup.pcap | `(objectcategory=organizationalUnit)` |
| 511 | 2022-05-10-sharphound_objectprops.pcap | `(|(|(|(|(|(|(samaccounttype=805306369)(objectClass=container))(samaccounttype=805306368))(|(|(|(samaccounttype=268435456)(samaccounttype=268435457))(samaccounttype=536870912))(samaccounttype=536870913)))(objectclass=domain))(object` |

https://github.com/BloodHoundAD/SharpHoundCommon/blob/d402833198a249f1aab7c8ca4ac47965807290ef/src/CommonLib/LDAPQueries/LDAPFilter.cs#L114

### Why is GPLink important? 

I will write about GPO in my future post more in depth, but in short, GPO is a set of rules for a group (domain/OU/site/...). Group Policies can include security options, registry keys, software installation, and scripts for startup and shutdown, meaning, every account under the group will have the same settings applied. GPLink is an attribute in AD Object that contains the GPO distinguished name value which this object is linked with. Below is an example 

![](assets/gpo-dn.png)

Although default sharphound only searches for OU objects, search filter isn't as important as having `gplink` in the attribute. If gplink is not part of the requested attribute, the attacker cannot identify the GPO linked to the OU

![](assets/gplink-attr.png)

### Alternate Attack Vector 

`(gplink=*)`

---

## Computer Enumeration

ComputerOnly collection method is combination of 
Computer Enumeration \| LocalGroup \| Session Enumeration. Since LocalGroup and Session Enumeration is covered as separate technique in this blog post, I will only cover Computer Enumeration portion of the attack. 

### Simulation 
 
 **Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | Filter |
|---|---|---|
| 511 | 2022-05-10-sharphound_computeronly.pcap | `(samaccounttype=805306369)` |

**Samaccounttype** is an attribute of AD object that uniquely defines an AD object type

- 268435456 SAM_GROUP_OBJECT
- 268435457 SAM_NON_SECURITY_GROUP_OBJECT
- 536870912 SAM_ALIAS_OBJECT
- 536870913 SAM_NON_SECURITY_ALIAS_OBJECT
- 805306368 SAM_NORMAL_USER_ACCOUNT
- 805306369 SAM_MACHINE_ACCOUNT
- 805306370 SAM_TRUST_ACCOUNT
- 1073741824 SAM_APP_BASIC_GROUP
- 1073741825 SAM_APP_QUERY_GROUP
- 2147483647 SAM_ACCOUNT_TYPE_MAX
Any of above types can be used to enumerate a specific type of accounts. 

For example, `(samaccounttype=805306368)` will return all user accounts from AD,

`(samaccounttype=805306369)` returns all computer accounts from AD

### Alternate Attack Vectors

`(objectClass=Comptuer)`
`(objectCategory=Computer)`

---

## SPN Enumeration

SPN scan attempts to enumerate all Service Principal Names of the domain to get an idea of what services are running in what computers.


### Simulation 
 
 **Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | Filter |
|---|---|---|
| 511 | 2022-05-20-sharphound-spntargets.pcap | `(&(samaccounttype=805306368)(serviceprincipalname=*))` |

Key filter = serviceprincipalname=*


### Alternate Attack Vectors
I'm not aware of any other ways of enumerating all SPNs. Let me know if there are other ways via email. 

one way to bypass simple filter detection is by targeting specific well known service names
`serviceprincipalname=SQL*`
or
`serviceprincipalname=CIFS*`

simple variations can be used to bypass low-hanging fruit network detection signatures

---

## Trust Enumeration
Trust enumeration is enumerating domain trusts. Domain trusts is defined as a relationship between two domains that enables users in one domain to be authenticated by a domain controller in another domain. This information allows attackers plan their attack onto another domain which current domain has trust relationship with


### Simulation 
 
 **Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | Filter |
|---|---|---|
| 523 | 2022-05-10-sharphound_trusts.pcap | `Filter: (objectclass=trusteddomain)` |

### Alternate Attack Vectors

domain trust enumeration can be done via RPC as well - https://docs.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsenumeratedomaintrustsa

---

## User Enumeration
User Enumeration as name suggests, enumerates all users in the domain. There are many ways this can be done both via LDAP and RPC.

Among Sharphound collection methods, only ObjectProps and ACL methods contain User Enumeration technique 

        ObjectProps = Computer Enum | Container Enum | User Enum | Group Enum | Domain Enum | OU Enum | GPO Enum 

Collection methods ObjectProps and ACL are basically enumerating everything except domain trusts via LDAP. 

https://github.com/BloodHoundAD/SharpHound/blob/af71c15e303a967ecf57808376165a4371809219/src/Producers/BaseProducer.cs#L39


### Simulation 
 
**Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | Filter |
|---|---|---|
| 511 | 2022-05-10-sharphound_objectprops.pcap | `(|(|(|(|(|(|(samaccounttype=805306369)(objectClass=container))(samaccounttype=805306368))(|(|(|(samaccounttype=268435456)(samaccounttype=268435457))(samaccounttype=536870912))(samaccounttype=536870913)))(objectclass=domain))(object` |


               


### Alternate Attack Vectors

| Description | Filter |
|---|---|
| get all users | `(objectClass=User)` |
| get all users | `(objectClass=Person)` |
| get all users | `(objectCategory=User)` | 
| get all users | `(objectCategory=Person)` |
| All disabled user objects | `(userAccountControl:1.2.840.113556.1.4.803:=2)` |
| All enabled user objects | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| All users with "Password Never Expires" set | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| All users not required to have a password | `(userAccountControl:1.2.840.113556.1.4.803:=32))` |
|All users with "Do not require kerberos preauthentication" enabled | `(userAccountControl:1.2.840.113556.1.4.803:=4194304))` |
| Accounts trusted for delegation (unconstrained delegation) | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| Accounts that are sensitive and not trusted for delegation | `(userAccountControl:1.2.840.113556.1.4.803:=1048574)` |
| Win32API | [SamrEnumerateUsersInDomain](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6bdc92c0-c692-4ffb-9de7-65858b68da75) |
| Win32API | [SamrGetMembersInGroup](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/3ed5030d-88a3-42ca-a6e0-8c12aa2fdfbd)|
| Win32API | [SamrQueryDisplayInformation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/c1458942-f2d5-4317-a888-abd27abad504)

Any of the above filters can be combined to enumerate users. This allows attackers to easily bypass signature based detection approaches. Then, **what can we do** from the blue side to defend against malicious reconnaissance attempts? 

---

# Ideas

There are many ways to make an LDAP filter complicated to make defense against malicious ldap queries very difficult. For example, 

Computer Enumeration simple filter: 
```
(objectclass=computer)
```

you could do something like below just to avoid ldap signature detection, but still get same response back
```
(|(|(|(|(objectclass=computer)(samaccounttype=805306369)(samaccounttype=805306369)(samaccounttype=805306369)(samaccounttype=805306369))))
```

Although static filters can work to defend against publicly known tools, it is also very easy to bypass. 

Let's brainstorm some ideas on how we could defend against malicious LDAP queries

## 1. Static Filters

We can tackle the problem by creating a bunch of static filters to alert on. This approach is the most bruteforcy way to handle this issue as this will require many many permutations to catch advanced attackers. For example, static filters must also consider the order of filters being put together. 

SPN enumeration filter
```
(&(samaccounttype=805306368)(serviceprincipalname=*))
```

Alternate SPN enumeration filter
```
(&(serviceprincipalname=*)(samaccounttype=805306368))
```

Imagine a filter that has 5 unqiue items inside. it will require 120 unique static filters to catch all combinations

Although viable and efficient to catch attackers that use tools with default configuration, this is not suitable for any attackers with intent to hide under the radar of blue teams. 

## 2. Parse out the query

LDAP queries are combined by `|`, `!`, and `&` operators. See more of LDAP Syntax details from [here](http://www.ldapexplorer.com/en/manual/109010000-ldap-filter-syntax.htm). If an environment can capture all network traffic and log LDAP filters, one could parse the LDAP filter down to individual parts and have a parser read individual parts of the ldap query to understand what this filter is looking for. For example 
```
(|(&(&(objectclass="some-nonexistant-class-value")(samaccounttype=805306369))(samaccounttype=805306368))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```
<!-- `(|(|(objectclass=computer)(samaccounttype=805306369)(samaccounttype=805306368)))` -->

First, we can parse this down to individual parts 
```
(
	(
		objectclass="some-nonexistant-class-value"
			AND
		samaccounttype=805306369
	)
	AND
	samaccounttype=805306368
)
OR
(!(userAccountControl:1.2.840.113556.1.4.803:=2))

```

A parser will be able to categorize each part of the filter as below
```
(
	(
		objectclass="some-nonexistant-class-value"
			AND
		Computer Enumeration
	)
	AND
	User Enumeration
)
OR
Enabled User Enumeration

```

Parser will then know that the client requested **at least** all "enabled users"


**Another Example**

```
(|(|(objectclass=computer)(samaccounttype=805306369)(objectcategory=computer)(samaccounttype=805306368)))
```

Simplified version of above query looks like this 

```
Computer Enumeration OR Computer Enumeration OR Computer Enumeration OR Computer Enumeration
```

Which is then de-duplicated by the parser as 

```
computer enumeration OR user enumeration
```


There are many cases this parser will need to be able to handle such as handling `!` operator and `&` operator that make the logic more complicated. However, a mature parser will be able to defend against most of malicious LDAP reconnaissance attacks. (Maybe I will create a parser in the future and link it here, but as of now I haven't created one, and I don't see any projects that attempt to parse the intention out of LDAP filters yet)

<!-- 
## 3. Watch the response 

However complicated the request filter might be, response might be the only concern we may have. Response contains the answer to this question: "what are we giving to the attacker?". Regardless of the request filter, if a client all the sudden retrieves a chunk of AD objects, we should be aware of what this client retrieved. 

For example, a client requests for all User Accounts via LDAP, but the attacker made the query very complicated to bypass the static filter detections. One could parse the response and figure out what type of objects were sent back and alarm if majority of users were sent back or users of critical group such as domain admins were sent back. 

Where can we get this data? 

One way to get this data is from decrypting network traffic from DC.

Another way is creating some sort of log that saves which AD objects were sent back each response. 
 -->

---

# DCERPC
 
## Local Admin \| PS Remote \| RDP \| DCOM

LocalGroups collection method collects various local groups from target computer. The default of sharphound LocalGroups collection method collects DCOM, RDP, LocalAdmin, and PSRemote users from the target computer

        LocalGroups = DCOM | RDP | LocalAdmin | PSRemote,

| Name | RID | Description |
|---|---|---|
| PSRemote | 580 | A built-in local group. Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user. |
| LocalAdmin | 544 | A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Admins group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Admins group also is added to the Administrators group. |
| RDP | 555 | An alias. Members in this group are granted the right to log on remotely. |
| DCOM | 562 | An alias. A group for COM to provide computer-wide access controls that govern access to all call, activation, or launch requests on the computer. |


This enumeration technique does not use LDAP. Rather it uses SAMR GetMembersInAlias RPC call to grab accounts. Since this technique is collecting local accounts, this technique is likely used against many workstations to collect local accounts of many workstations to map which accounts have admin rights on which workstations.

Key for detecting this behavior is RID. RID shows up in OpenAlias call

![](assets/samr-openalias.png)

With RID, we can figure out which accounts the attacker is trying to enumerate.

### Simulation 

**Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | RPC Call |
|---|---|---|
| 433 | 2022-05-10-sharphound_localgroup.pcap | SamrOpenAlias(544) |
| 511 | 2022-05-10-sharphound_rdp.pcap | SamrOpenAlias(555) |
| 609 | 2022-05-10-sharphound_dcom.pcap | SamrOpenAlias(562) |
| 461 | 2022-05-10-sharphound_localgroup.pcap | SamrOpenAlias(580) |



### Alternate Attack Vectors
There aren't really good alternatives for this technique. Let me know if there are other ways to enumerate local users. 

---

## Session Enumeration

Session collection method enumerates all sessions connected to the target server. This technique uses RPC call NetrSessionEnum. Details about the RPC call can be found in the MS-DOC below

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/02b1f559-fda2-4ba3-94c2-806eb2777183

### Simulation 
**Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | RPC Call |
|---|---|---|
| 433 | 2022-05-10-sharphound_localgroup.pcap | NetSessEnum |

Session Enumeration technique is very straightforward. Client sends NetrSessionEnum call. Depending on different levels of information client requests, the server can return session information such as computer name, user name, open files, and pipes. This information about active session between domain joined computers is valuable for attackers. 

This behavior, just like LocalGroups collection method, is likely used against many computers to map the relationship between computers and to gain knowledge of how each clients are connected to the other computer. Thus, looking for a large # of this RPC call can be a clue for identifying malicious behavior. 


### Alternate Attack Vectors
There aren't really good alternatives for this technique. Let me know if there are other ways to enumerate active sessions. 

---

## Loggedon User Enumeration

Loggedon collection method gathers information about users who are currently active on target server.




### Simulation 
**Attacker**
- IP: 192.168.10.101
- OS: Windows 10 Pro
- OS Version: 19044.1706
- Sharphound: 1.0.3

**Victim**
- IP: 192.168.10.11
- OS: Windows Server 2019
- OSVersion: 10.0.17763

| Frame # | Pcap | RPC Call |
|---|---|---|
| 609 | 2022-05-10-sharphound_loggedon.pcap | NetWkstaEnumUsers |

Same behavior as other techniques that uses RPC. Loggedon User Enumeration uses [NetWkstaEnumUsers RPC Call](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/55118c55-2122-4ef9-8664-0c1ff9e168f3) to enumerate users who are currently active on target server.


### Alternate Attack Vectors
There aren't really good alternatives for this technique. Let me know if there are other ways to enumerate logged on users. 

---

## Ideas

Techniques to defend against Sharphound RPC Active Directory Reconnaissance are straightforward. As I've described above, most of techniques used in sharphound that use RPC are related to local users or data that is unique to each computer & not saved in central place like Domain Controller. Thus, above techniques can be identified easily on the network, the blue side just needs to watch out for a client that uses one of the RPC calls above against many workstations.

