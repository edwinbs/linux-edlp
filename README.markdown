## Welcome

We are building an endpoint Data Leak Prevention (DLP) enforcement engine for Linux, for a CS5231 Systems Security course project in National University of Singapore (NUS).

## Motivation

In recent years, data leak has become a serious concern for enterprises, as targeted attacks and disgruntled employees continue to divulge sensitive and high value information outside of organizations. To address these concerns, Data Leak Prevention (DLP) technology emerged around 2007 and has attracted a number of commercial solutions from industry leaders, including Symantec, McAfee, and RSA, along with several startups.

The industry sees a DLP solution as a collection of three types of protection: (1) data-at-rest, referring to data residing in a persistent storage system, such as a server, (2) data-in-motion, which concerns with preventing eavesdropping, and (3) data-at-endpoints, which deals with preventing sensitive data from being copied out of end-user machines.

As far as endpoint protection is concerned, the market dominance of Microsoft Windows has led commercial software vendors to focus only on that platform. Unlike the protection mechanisms for data-at-rest and data-in-motion, which basically relies on encryption, endpoint DLP requires more sophisticated strategies on its enforcement engine to track the state of sensitive data as it is being used in an endpoint, which generally relies on hooking system calls. As such, porting a solution designed for Windows to Linux or Mac OS is likely to be non-trivial.

In this project, we will investigate how an enforcement engine for endpoint DLP can be built for Linux. To achieve this, we will have to (1) find a reliable way to hijack system calls in Linux, and (2) build an engine that can track the transformation of data in a Linux system. We will deliver a proof of concept that demonstrates a working endpoint DLP enforcement engine in a Linux distribution.

## Scope

We will build a proof-of-concept for an endpoint DLP enforcement engine that will run on a Linux distribution. The following functionalities will be delivered:
* File open operations on a classified file will always be logged, including both when the operation is done manually (by a user) or automatically (e.g. by a malware)
* File copy and move operations to an external location (smb, USB drive, or CD/DVD) will be filtered for classified files
* Browsers and email clients will not be allowed to upload or attach classified files
* Screenshots are disallowed when a classified file is opened
* Tracking of data movement and transformation, including the use of clipboard and encryption, and blocking the subsequent attempt to write the transformed data
