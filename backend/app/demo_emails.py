DEMO_EMAILS = [
    {
        "id": 1,
        "from": "security-alert@paypa1-support.com",
        "subject": "Urgent: Your PayPal Account Has Been Limited",
        "preview": "Dear Customer, we have detected unusual activity on your account...",
        "time": "09:14",
        "body": "Dear Customer,\n\nWe have detected unusual activity on your PayPal account and, as a result, we have temporarily limited your account access. This is a security measure to protect you from unauthorized use.\n\nTo restore full access to your account, you must verify your identity immediately by clicking the link below and providing your account credentials, including your password and credit card number. If you do not verify your account within 24 hours, your account will be permanently suspended and all pending transactions will be cancelled.\n\nWe take the security of our customers very seriously and apologize for any inconvenience this may cause. Please click here to verify your account now. Failure to respond will result in permanent account termination.\n\nDo not ignore this message, as your account has been flagged for suspicious activity. Your immediate action is required to avoid suspension.\n\nThank you for being a valued PayPal customer.\nPayPal Security Team",
        "label": "Phishing Email",
    },
    # The two legitimate emails are fictional (names, company, list). They replace
    # corpus emails that contained real people's names. Domains use the reserved
    # example.com / example.org, which can never belong to a real person.
    {
        "id": 2,
        "from": "david.miller@example.com",
        "subject": "Welcome to Global Risk Operations",
        "preview": "Congratulations on your new role. In case you have not heard, I moved to Houston...",
        "time": "08:20",
        "body": "Hi Sarah,\n\ncongratulations on your new role! In case you have not heard yet, I moved to the risk assessment group in Houston last month, so I expect we will work together from time to time. I am looking forward to it.\n\nFor some context: with our growing presence in the wholesale energy business, management has set up a global risk operations function to keep internal controls consistent across all locations. It reports to the vice president of operations, and the first team meeting is planned for next Thursday.\n\nBest regards,\nDavid",
        "label": "Safe Email",
    },
    {
        "id": 3,
        "from": "kate@lists.example.org",
        "subject": "Re: storage driver maintainer",
        "preview": "My impression is that the storage driver has gone downhill since the long-time maintainer stepped back...",
        "time": "08:00",
        "body": "I read the kernel mailing list now and then, and my impression is that the storage driver has gone downhill since its long-time maintainer stepped back. The new maintainer seems to struggle to move development forward without breaking things.\n\nWhich raises the question: why change a setup that worked? If it ain't broke, don't fix it.\n\nTo be fair, the driver has to support hundreds of quirky chipsets and drives, so some messiness is unavoidable. A few months of reading that code can make anyone grumpy.\n\nKate\nLinux Users Group",
        "label": "Safe Email",
    },
    {
        "id": 4,
        "from": "it-helpdesk@your-company-portal.net",
        "subject": "Action Required: Password Expiry Notice",
        "preview": "Your corporate password will expire in 2 hours. Immediate action required...",
        "time": "08:45",
        "body": "Dear Employee,\n\nThis is an automated message from the IT Security Department to inform you that your corporate network password is scheduled to expire in 2 hours. Failure to update your password immediately will result in loss of access to all company systems, including email, file storage and internal applications.\n\nTo prevent disruption to your work, you must click the link below and confirm your current password before entering a new one. This process is mandatory for all employees and must be completed before the deadline. Your account has been flagged for immediate password reset due to a recent security audit.\n\nPlease provide your employee ID, username and current password to proceed. If you have already updated your password, please disregard this message. For assistance, contact the IT Helpdesk at the number below.\n\nThis link will expire in 2 hours, so please act immediately to avoid being locked out of all company systems.\n\nIT Security Department",
        "label": "Phishing Email",
    },
    {
        "id": 5,
        "from": "claims@lottery-international-winner.com",
        "subject": "Congratulations: You Have Been Selected as a Prize Winner",
        "preview": "We are pleased to inform you that your email address has won $1,000,000...",
        "time": "08:10",
        "body": "Congratulations, Dear Winner!\n\nWe are pleased to inform you that your email address has been selected as the winner of our International Email Lottery Promotion. Your email was chosen from over 50 million email addresses worldwide, and you have won the sum of ONE MILLION UNITED STATES DOLLARS ($1,000,000).\n\nTo claim your prize, you are required to contact our claims agent immediately and provide your full name, home address, telephone number, date of birth, occupation and bank account details for the transfer of your winnings. Please note that you must claim your prize within 72 hours, or it will be forfeited and awarded to the next selected winner.\n\nTo begin the claims process, please reply to this email with the required information or contact our agent directly. All prize claims are handled in strict confidence.\n\nA processing fee of $150 is required to release your winnings and cover administrative costs. This fee must be paid via wire transfer before your prize can be disbursed.\n\nCongratulations again on your selection. We look forward to processing your claim.\n\nInternational Lottery Commission\nClaims Department",
        "label": "Phishing Email",
    },
]


def load_emails() -> list[dict]:
    return DEMO_EMAILS
