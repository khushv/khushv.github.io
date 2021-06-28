---
title: Thoughts on the AWS Security Specialty Certification
author: Khush V
date: 2021-06-22 00:00:00 +0000
categories: [AWS, Security Specialty Certification]
tags: [AWS, cloud, certification]
---

# Thoughts on the AWS Security Specialty Certification

This is a brief post about In 2019, I undertook the AWS Certified Solutions Architect – Professional certification. I wanted to solidify my knowledge of AWS I had gained in my previous life as a developer and largely I felt it gave me a breadth, but not depth overview .of all the different services AWS had to offer.

Since then, I've lead and conducted numerous AWS security assessments as part of my job. This year, as a challenge to myself and partly as a way of building on my AWS knowledge further, I decided to take the AWS Security Specialty exam. AWS recommends a minimum of 5 years of IT security experience, specifically in designing and implementing security solutions and at least 2 years of hands-on experience securing AWS workloads. 

## Breakdown of exam

The exam is comprised of 65 multiple choice questions in 170 (2hr 50) minutes. There's different content domains the exam covers and it's broken down in the following:

![Breakdown of AWS exam](/assets/img/aws_1.PNG)
_AWS Security Specialty exam breakdown._

Due to COVID-19, there was an option to take the exam online remotely with a computer installed with proctoring software. There was an examination centre close to me and it was open, so I decided to take the exam there.

## Preparation 

I already had a CloudAcademy subscription and began prepping for the exam by watching the AWS Security Course course videos. I don't quite recall how many hours of content there is, but its substantial that it took me a couple of weeks to go through it in the evenings and weekends. In my personal opinion, the course content wasn't up to scratch and needs a lot of improvement. A lot of the videos only provide a cursory introduction to an AWS service and not how it relates from a security point of view. The labs were ok at gaining an understanding of the course material. Nevertheless, it did help a bit refreshing some bits of AWS I had forgotten about. 

The second thing I did was read the many whitepapers AWS has published. The most useful ones I found were:

https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf
https://d1.awsstatic.com/whitepapers/aws-kms-best-practices.pdf
https://d1.awsstatic.com/whitepapers/compliance/AWS_Security_at_Scale_Governance_in_AWS_Whitepaper.pdf
https://d1.awsstatic.com/whitepapers/compliance/AWS_Security_at_Scale_Logging_in_AWS_Whitepaper.pdf

Other resources I found helpful were:
- Re:Invent videos
- Technical Deep Dives videos
- AWS documentation  
- Service FAQs

I also took the free AWS Security Specialty Official Course[^AWS Official Course], to cover all my bases in case I missed something. It was fairly short, with two hours worth of content and I found it contained no new content that I didn't know already. 


## Topics of note

There's a few topics worth mentioning, that I found were assessed in detail. These were:

#### IAM policies

Service control policies, permissions boundaries, trust policies, resourced base policies, roles, ACLs oh my! There's a lot of different types of policies that can be applied ton manage broad permissions and also more granular based permissions. My recommendation is to get good  at understanding the different policies, know your action from your resource, where they are used and the different formats of policies. 

#### Encryption/KMS 

I found an emphasis on encryption of data, particularly at rest and in transit. Those studying for the test would benefit from understanding the encryption mechanisms offered by various AWS services, such as encryption in buckets, load balancers, EBS etc.

AWS Key Management Service is topic worth learning in depth about. It's critical to understand the various concepts of KMS, the pros and cons of using different types of Customer Masker Keys, etc. Whilst I was preparing and taking the exam, KMS was only supported as a single region service and keys could not be shared across regions. That has changed recently, with AWS introducing multi-region keys, which replicate keys across regions (introduced 16th June 2021.

#### Logging

There are three services that fall into this category - CloudTrail, CloudWatch and I'm putting AWS Config in this category as well. If you know how to set up trails, trigger Lambda functions from configuration changes and metrics, you'll be golden.

 
#### Federation & Authentication

I've noticed federation for AWS access becoming increasingly popular in cloud security assessments. Therefore it's not a surprise that the exam covers the different ways to federate access to AWS, whether thats using SAML, OpenID or Active Directory. Cognito also makes an appearance, so worth brushing up on this.



## Conclusion

It took me a while to get back into the swing of AWS exams. They're very distinct in the format of their questions, and it always takes me a while to begin understanding the question and pick out the keywords to understand what it's really asking.

As exams go, this one was pretty tough. I found the Solutions Architect pretty straight forward, and therefore was expecting to finish this one with an hour to spare. However, I ended up taking up almost all of the allocated time double checking my answers. This could be due to the short preparation time I had for this certification but I am happy to announce however, that I passed. 



## Links

[^AWS Security Specialty Certification syllabus]: https://d1.awsstatic.com/training-and-certification/docs-security-spec/AWS-Certified-Security-Specialty_Exam-Guide.pdf
[^AWS Official Course]: https://www.aws.training/Details/eLearning?id=34786