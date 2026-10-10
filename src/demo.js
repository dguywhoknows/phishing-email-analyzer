/* Sample messages (fictional companies) for the scanner and the training game. */
var SAMPLES = {
  'Bank phish': `From: "Northwind Bank Security" <alerts@northwlnd-bank.com>
Reply-To: support-desk@mail-verify-center.top
Return-Path: <bounce@mail-verify-center.top>
Subject: URGENT: Your account has been suspended
Message-ID: <8823.1101@relay.verify-center.top>
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=mail-verify-center.top; dkim=none; dmarc=fail header.from=northwlnd-bank.com
Received: from mx.example.net (mx.example.net [198.51.100.20]) by inbox.example.net with LMTP; Tue, 6 Oct 2026 10:00:12 +0000
Received: from relay.verify-center.top (unknown [203.0.113.7]) by mx.example.net with ESMTP; Tue, 6 Oct 2026 10:00:03 +0000
Received: from localhost (static.45.33.example.vps [192.0.2.45]) by relay.verify-center.top with SMTP; Tue, 6 Oct 2026 09:58:41 +0000

Dear Customer,

We detected unusual sign-in activity on your Northwind Bank account. For your protection, your account has been suspended.

To restore access you must verify your identity within 24 hours, otherwise your account will be closed permanently.

<a href="http://northwindbank.secure-login.verify-id.top/login?session=88231">https://www.northwindbank.com/secure</a>

You may also need to open the attached Statement_Review.html to confirm recent transactions.

Thank you,
Northwind Bank Security Team`,
  'Real newsletter': `From: "Contoso Weekly" <news@contoso.com>
Reply-To: news@contoso.com
Return-Path: <bounces@contoso.com>
Subject: This week: 5 tips for better sleep
Message-ID: <a81c2.weekly@contoso.com>
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=contoso.com; dkim=pass header.d=contoso.com; dmarc=pass header.from=contoso.com
Received: from mail.contoso.com (mail.contoso.com [198.51.100.80]) by mx.example.net with ESMTPS; Mon, 5 Oct 2026 14:02:10 +0000

Hi Sam,

Here's your weekly roundup. This issue covers sleep science, a new running plan, and reader questions.

Read the full article: https://www.contoso.com/blog/sleep-tips

You're receiving this because you subscribed at contoso.com. Manage preferences: https://www.contoso.com/account/email

Cheers,
The Contoso team`,
  'Gift-card scam': `From: "Dana Whitfield (CEO)" <dana.whitfield.ceo@gmail.com>
Subject: Quick favor - are you at your desk?

Hi,

I'm in back-to-back meetings and need a quick favor handled immediately. I need you to purchase 5 Apple gift cards ($200 each) for a client appreciation. It's time-sensitive and I'll reimburse you today.

Scratch off the codes and send me photos as soon as possible. Please keep this confidential for now.

Thanks,
Dana

Sent from my iPhone`,
};

/* Training set: answer is 'phish' or 'legit', with the tell a careful reader should notice. */
var TRAINING = [
  { answer: 'phish', tell: 'The link text shows the real site, but the href goes to a .top domain. Hover before you click.', raw: `From: "Fabrikam Payroll" <payroll@fabrikam-hr.top>
Subject: Action required: confirm your direct deposit

Hello,

Payroll is migrating systems. Confirm your account details before Friday or your salary payment may be delayed.

<a href="https://fabrikam-payroll.verify-staff.top/login">https://payroll.fabrikam.com</a>

HR Operations` },
  { answer: 'legit', tell: 'Consistent sender and link domains, no request for credentials, and you can reach the same page by typing the address yourself.', raw: `From: "Tailspin Toys" <orders@tailspintoys.com>
Subject: Your order #48213 has shipped

Hi Alex,

Good news: your order is on its way. Track it any time from your account: https://www.tailspintoys.com/orders/48213

Thanks for shopping with us.` },
  { answer: 'phish', tell: 'Display name says IT, the address is a free webmail account, and it pressures you to "verify" a password.', raw: `From: "IT Service Desk" <it.helpdesk.team@outlook.com>
Subject: Password expires today

Your mailbox password expires today. To keep your account, log in to verify your password immediately:

http://192.0.2.14/owa/login

IT Service Desk` },
  { answer: 'phish', tell: 'The domain "rnicrosoft" uses "rn" to look like "m". Read domains letter by letter.', raw: `From: "Microsoft 365" <no-reply@rnicrosoft-support.com>
Subject: Unusual sign-in activity

We detected unusual sign-in activity. Review the activity now or your account will be locked.

https://rnicrosoft-support.com/review` },
  { answer: 'legit', tell: 'An expected calendar note from a colleague on the company domain, with no links or requests.', raw: `From: "Priya Raman" <priya.raman@woodgrove.com>
Subject: Moving our 1:1 to Thursday

Hi Jordan,

Can we move our 1:1 to Thursday at 2pm? Tuesday is packed. Same room as usual.

Thanks,
Priya` },
  { answer: 'phish', tell: 'A refund you never asked for, a link shortener that hides where it goes, and a deadline.', raw: `From: "Revenue Service Refunds" <refunds@tax-refund-portal.xyz>
Subject: You have an unclaimed refund of $812.40

Dear taxpayer,

You are eligible for a refund of $812.40. Claim it within 48 hours: https://bit.ly/3refund-claim

Revenue Service` },
  { answer: 'legit', tell: 'Matches a sign-in you just made and tells you to go to the site yourself instead of clicking.', raw: `From: "Litware Accounts" <security@litware.com>
Subject: New sign-in on Windows

Hi Morgan,

We noticed a new sign-in to your Litware account from Windows (Chrome) in Toronto. If this was you, you don't need to do anything.

If it wasn't, open litware.com yourself and change your password from the account page.` },
  { answer: 'phish', tell: 'Shared-document lure with an .html attachment, which is a common way to deliver a fake login page.', raw: `From: "DocuShare" <share@docs-notify.click>
Subject: Invoice attached: payment overdue

You have received a secure document. Open the attached Invoice_0921.html to review and sign.

This link expires today.` },
];
