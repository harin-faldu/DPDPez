"""DPDP Rules 2025 statutory text.  OWNER: Prerana

SOURCE OF TEXT (verbatim, no paraphrase):
    The Digital Personal Data Protection Rules, 2025, notified by the Ministry
    of Electronics and Information Technology vide G.S.R. 846(E) dated the 13th
    November, 2025, published in the Gazette of India, Extraordinary, Part II,
    Section 3, Sub-section (i). English text, pages 24 to 36 of the bilingual
    gazette.
    URL: https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf
    Retrieved: 2026-09-26.

WHICH VERSION THIS IS: the FINAL NOTIFIED Rules, not the draft. The draft rules
were published for consultation vide G.S.R. 02(E) dated 3 January 2025; they
were superseded by the notified rules above. Everything here is the notified
text.

NUMBERING CHANGED BETWEEN DRAFT AND FINAL, AND IT MATTERS:
    The notified Rules contain TWENTY THREE rules, not twelve, and two of the
    numbers the build notes assumed have moved:
        Additional obligations of Significant Data Fiduciary   draft 11 -> FINAL 13
        Rights of Data Principals (rights exercise procedure)  draft 12 -> FINAL 14
    In the notified Rules, rule 11 is verifiable consent for a person with
    disability and rule 12 is exemptions for a child's personal data. Any
    checker that pins RETRIEVAL_SECTION_IDS to "rule_11" for SDF duties or
    "rule_12" for data principal rights will retrieve and cite the wrong
    provision. Use "rule_13" and "rule_14".

Commencement is staggered by the notified rule 1: rules 1, 2 and 17 to 21 on
publication, rule 4 one year after, and rules 3, 5 to 16, 22 and 23 eighteen
months after.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleText:
    section_id: str
    number: int
    title: str
    text: str

    @property
    def citation_label(self) -> str:
        return f"DPDP Rules 2025, Rule {self.number}"


RULES: list[RuleText] = [
    RuleText(
        section_id="rule_1",
        number=1,
        title="Short title and commencement",
        text=(
            "(1) These rules may be called the Digital Personal Data Protection Rules, 2025. (2) "
            "Rules 1, 2 and 17 to 21 shall come into force on the date of their publication in the "
            "Official Gazette. (3) Rule 4 shall come into force one year after the date of "
            "publication of this Gazette. (4) Rules 3, 5 to 16, 22 and 23 shall come into force "
            "eighteen months after the date of publication of this Gazette."
        ),
    ),
    RuleText(
        section_id="rule_2",
        number=2,
        title="Definitions",
        text=(
            "(1) In these rules, unless the context otherwise requires, – (a) “Act” means the Digital "
            "Personal Data Protection Act, 2023 (22 of 2023); (b) “techno-legal measures” means as "
            "referred to under rules 20 and 22; (c) “user account” means the online account "
            "registered by the Data Principal with the Data Fiduciary, and includes any profiles, "
            "pages, handles, email address, mobile number and other similar presences by means of "
            "which such Data Principal is able to access the services of such Data Fiduciary; and (d) "
            "“verifiable consent” means a consent as specified in rule 10 or 11. (2) The words and "
            "expressions used in these rules and not defined, but defined in the Act, shall have the "
            "same meanings respectively assigned to them in the Act."
        ),
    ),
    RuleText(
        section_id="rule_3",
        number=3,
        title="Notice given by Data Fiduciary to Data Principal",
        text=(
            "The notice given by the Data Fiduciary to the Data Principal shall— (a) be presented and "
            "be understandable independently of any other information that has been, is or may be "
            "made available by such Data Fiduciary; (b) give, in clear and plain language, a fair "
            "account of the details necessary to enable the Data Principal to give specific and "
            "informed consent for the processing of her personal data, which shall include, at the "
            "minimum, — (i) an itemised description of such personal data; and (ii) the specified "
            "purpose or purposes of, and specific description of the goods or services to be provided "
            "or uses to be enabled by, such processing; and (c) give, the particular communication "
            "link for accessing the website or app, or both, of such Data Fiduciary, and a "
            "description of other means, if any, using which such Data Principal may— (i) withdraw "
            "her consent, with the ease of doing so being comparable to that with which such consent "
            "was given; (ii) exercise her rights under the Act; and (iii) make a complaint to the "
            "Board."
        ),
    ),
    RuleText(
        section_id="rule_4",
        number=4,
        title="Registration and obligations of Consent Manager",
        text=(
            "(1) A person who fulfils the conditions for registration of Consent Managers set out in "
            "Part A of First Schedule may apply to the Board for registration as a Consent Manager by "
            "furnishing such particulars and such other information and documents as the Board may "
            "publish in this behalf on its website. (2) On receipt of such application, the Board may "
            "make such inquiry as it may deem fit to satisfy itself regarding fulfilment of the "
            "conditions set out in Part A of First Schedule, and if it— (a) is satisfied, register "
            "the applicant as a Consent Manager, under intimation to the applicant, and publish on "
            "its website the particulars of such Consent Manager; or (b) is not satisfied, reject the "
            "application and communicate the reasons for the rejection to the applicant. (3) The "
            "Consent Manager shall have obligations as specified in Part B of First Schedule. (4) If "
            "the Board is of the opinion that a Consent Manager is not adhering to the conditions and "
            "obligations under this rule,it may, after giving an opportunity of being heard, inform "
            "the Consent Manager of such non- adherence and direct the Consent Manager to take "
            "measures to ensure adherence. (5) The Board may, if it is satisfied that it is necessary "
            "so to do in the interests of Data Principals, after giving the Consent Manager an "
            "opportunity of being heard, by order, for reasons to be recorded in writing, — (a) "
            "suspend or cancel the registration of such Consent Manager; and (b) give such directions "
            "as it may deem fit to that Consent Manager, to protect the interests of the Data "
            "Principals. (6) The Board may, for the purposes of this rule, require the Consent "
            "Manager to furnish such information as the Board may call for."
        ),
    ),
    RuleText(
        section_id="rule_5",
        number=5,
        title="Processing of personal data for provision or issue of subsidy, benefit, service, certificate, licence or permit by State and its instrumentalities",
        text=(
            "(1) Processing the personal data of a Data Principal under this rule shall be done "
            "following the standards specified in Second Schedule. (2) In this rule and the Second "
            "Schedule, the reference to any subsidy, benefit, service, certificate, licence or permit "
            "that is provided or issued— (a) under law shall be construed as a reference to provision "
            "or issuance of such subsidy, benefit, service, certificate, licence or permit in "
            "exercise of any power of or the performance of any function by the State or any of its "
            "instrumentalities under any law for the time being in force; (b) under policy shall be "
            "construed as a reference to provision or issuance of such subsidy, benefit, service, "
            "certificate, licence or permit under any policy or instruction issued by the Central "
            "Government or a State Government in exercise of its executive power; and (c) using "
            "public funds shall be construed as a reference to provision or issuance of such subsidy, "
            "benefit, service, certificate, licence or permit by incurring expenditure on the same "
            "from, or with accrual of receipts to, — (i) in case of the Central Government or a State "
            "Government, the Consolidated Fund of India or the Consolidated Fund of the State or the "
            "public account of India or the public account of the State; or (ii) in case of any local "
            "or other authority within the territory of India or under the control of the Government "
            "of India or of any State, the fund or funds of such authority."
        ),
    ),
    RuleText(
        section_id="rule_6",
        number=6,
        title="Reasonable security safeguards",
        text=(
            "(1) A Data Fiduciary shall protect personal data in its possession or under its control, "
            "including in respect of any processing undertaken by it or on its behalf by a Data "
            "Processor, by taking reasonable security safeguards to prevent personal data breach, "
            "which shall include, at the minimum, — (a) appropriate data security measures, such as "
            "securing of personal data through encryption, obfuscation, masking or the use of virtual "
            "tokens mapped to that personal data; (b) appropriate measures to control access to the "
            "computer resources used by such Data Fiduciary or such a Data Processor, wherever "
            "applicable; (c) visibility on the accessing of such personal data, through appropriate "
            "logs, monitoring and review, for enabling detection of unauthorised access, its "
            "investigation and remediation to prevent recurrence; (d) reasonable measures for "
            "continued processing in the event of confidentiality, integrity or availability of such "
            "personal data being compromised as a result of destruction or loss of access to personal "
            "data or otherwise, such as by way of data-backups; (e) for enabling the detection of "
            "unauthorised access, its investigation, remediation to prevent recurrence and continued "
            "processing in the event of such a compromise, retain such logs and personal data for a "
            "period of one year, unless compliance with any law for the time being in force requires "
            "otherwise; (f) appropriate provision in the contract entered into between such Data "
            "Fiduciary and such a Data Processor, wherever applicable, for taking reasonable security "
            "safeguards; and (g) appropriate technical and organisational measures to ensure "
            "effective observance of security safeguards. (2) In this rule, the expression “computer "
            "resource” shall have the same meaning as is assigned to it in Information Technology "
            "Act, 2000 (21 of 2000)."
        ),
    ),
    RuleText(
        section_id="rule_7",
        number=7,
        title="Intimation of personal data breach",
        text=(
            "(1) On becoming aware of any personal data breach, the Data Fiduciary shall, to the best "
            "of its knowledge, intimate to each affected Data Principal, in a concise, clear and "
            "plain manner and without delay, through her user account or any mode of communication "
            "registered by her with the Data Fiduciary, — (a) a description of the breach, including "
            "its nature, extent and the timing of its occurrence; (b) the consequences relevant to "
            "her, that are likely to arise from the breach; (c) the measures implemented and being "
            "implemented by the Data Fiduciary, if any, to mitigate risk; (d) the safety measures "
            "that she may take to protect her interests; and (e) business contact information of a "
            "person who is able to respond on behalf of the Data Fiduciary, to queries, if any, of "
            "the Data Principal. (2) On becoming aware of any personal data breach, the Data "
            "Fiduciary shall intimate to the Board, — (a) without delay, a description of the breach, "
            "including its nature, extent, timing and location of occurrence and the likely impact; "
            "(b) within seventy-two hours of becoming aware of the breach, or within such longer "
            "period as the Board may allow on a request made in writing in this behalf, — (i) updated "
            "and detailed information in respect of such description; (ii) the broad facts related to "
            "the events, circumstances and reasons leading to the breach; (iii) measures implemented "
            "or proposed, if any, to mitigate risk; (iv) any findings regarding the person who caused "
            "the breach; (v) remedial measures taken to prevent recurrence of such breach; and (vi) a "
            "report regarding the intimations given to affected Data Principals."
        ),
    ),
    RuleText(
        section_id="rule_8",
        number=8,
        title="Time period for specified purpose to be deemed as no longer being served",
        text=(
            "(1) A Data Fiduciary, who is of such class and is processing personal data for such "
            "corresponding purposes as are specified in Third Schedule, shall erase such personal "
            "data, unless its retention is necessary for compliance with any law for the time being "
            "in force, or, for the corresponding time period specified in the Third Schedule, if the "
            "Data Principal neither approaches such Data Fiduciary for the performance of the "
            "specified purpose nor exercises her rights in relation to such processing. (2) At least "
            "forty-eight hours before completion of the time period for erasure of personal data "
            "under this rule, the Data Fiduciary shall inform the Data Principal that such personal "
            "data shall be erased upon completion of such period, unless she logs into her user "
            "account or otherwise initiates contact with the Data Fiduciary for the performance of "
            "the specified purpose or exercises her rights in relation to the processing of such "
            "personal data. (3) Without prejudice to sub-rules (1) and (2), a Data Fiduciary shall "
            "retain, in respect of any processing of personal data undertaken by it or on its behalf "
            "by a Data Processor, such personal data, associated traffic data and other logs of the "
            "processing for a minimum period of one year from the date of such processing, for the "
            "purposes as specified in the Seventh Schedule, after which the Data Fiduciary shall "
            "cause such personal data and logs to be erased, unless further retention is required for "
            "compliance with any other law for the time being in force or notified by the Government. "
            "Illustration. Case 1: X, a Data Principal purchases an e-book on an e-book platform Y. "
            "Once delivery is completed, the specified purpose of processing is served. The platform "
            "Y must retain the order details, personal data, and logs of the processing (such as "
            "order confirmation, payment, and delivery events) for at least one year from the date of "
            "the transaction, even if X deletes her account. Case 2: X, a company engages a cloud "
            "service provider C as its Data Processor to host customer records. X as the Data "
            "Fiduciary, is required to ensure that the C also retains the data and associated logs "
            "for at least one year before erasure, unless any other applicable law requires a longer "
            "period."
        ),
    ),
    RuleText(
        section_id="rule_9",
        number=9,
        title="Contact information of person to answer questions about processing",
        text=(
            "Every Data Fiduciary shall prominently publish on its website or app, and mention in "
            "every response to a communication for the exercise of the rights of a Data Principal "
            "under the Act, the business contact information of the Data Protection Officer, if "
            "applicable, or a person who is able to answer on behalf of the Data Fiduciary the "
            "questions of the Data Principal about the processing of her personal data."
        ),
    ),
    RuleText(
        section_id="rule_10",
        number=10,
        title="Verifiable consent for processing of personal data of child",
        text=(
            "(1) A Data Fiduciary shall adopt appropriate technical and organisational measures to "
            "ensure that verifiable consent of the parent is obtained before the processing of any "
            "personal data of a child and shall observe due diligence, for checking that the "
            "individual identifying herself as the parent is an adult who is identifiable if required "
            "in connection with compliance with any law for the time being in force in India, by "
            "reference to— (a) reliable details of identity and age of the individual available with "
            "the Data Fiduciary; or (b) details of identity and age, voluntarily provided — (i) by "
            "the individual; or (ii) through a virtual token mapped to such details, which is issued "
            "by an authorised entity. (2) In this rule, the expression— (a) “adult” shall mean an "
            "individual who has completed the age of eighteen years; (b) “authorised entity\" shall "
            "mean — (i) an entity entrusted by law or by the Central Government or by the State "
            "Government with the issuance of details of the identity and age or a virtual token "
            "mapped to such details; or (ii) a person appointed or permitted by the entity specified "
            "under clause (i), for such issuance, and also includes details of identity and age or "
            "token made available and verified by a Digital Locker Service Provider; (c) “Digital "
            "Locker service provider” shall mean such intermediary, including a body corporate or an "
            "agency of the appropriate Government, as may be notified by the Central Government, in "
            "accordance with the rules made in this regard under the Information Technology Act, 2000 "
            "(21 of 2000); Illustration. C is a child, P is a parent, and DF is a Data Fiduciary. A "
            "user account of C is sought to be created on the online platform of DF, by processing "
            "the personal data of C. Case 1: C informs DF that she is a child and declares P as her "
            "parent. DF shall enable P to identify herself through its website, app or other "
            "appropriate means. P identifies herself as the parent and informs DF that she is a "
            "registered user on DF’s platform and has previously made available her identity and age "
            "details to DF. Before processing C’s personal data for the creation of her user account, "
            "DF shall check to confirm that it holds reliable identity and age details of P and that "
            "P is an identifiable adult. Case 2: C informs DF that she is a child and declares P as "
            "her parent. DF shall enable P to identify herself through its website, app or other "
            "appropriate means. P identifies herself as the parent and informs DF that she herself is "
            "not a registered user on DF’s platform. Before processing C’s personal data for the "
            "creation of her user account, DF shall, by reference to identity and age details issued "
            "by an entity entrusted by law or the Government with maintenance of the said details or "
            "to a virtual token mapped to the identity and age, check that P is an identifiable "
            "adult. P may voluntarily make such details available using the services of a Digital "
            "Locker service provider. Case 3: P is opening an account for C and identifies herself as "
            "C’s parent and informs DF that she is a registered user on DF’s platform and has "
            "previously made available her identity and age details to DF. Before processing C’s "
            "personal data for the creation of her user account, DF shall check to confirm that it "
            "holds reliable identity and age details of P and that P is an identifiable adult. Case "
            "4: P is opening an account for C and identifies herself as C’s parent and informs DF "
            "that she herself is not a registered user on DF’s platform. Before processing C’s "
            "personal data for the creation of her user account, DF shall, by reference to identity "
            "and age details issued by an entity entrusted by law or the Government with maintenance "
            "of the said details or to a virtual token mapped to the identity and age, check that P "
            "is an identifiable adult. P may voluntarily make such details available using the "
            "services of a Digital Locker service provider."
        ),
    ),
    RuleText(
        section_id="rule_11",
        number=11,
        title="Verifiable consent for processing of personal data of person with disability who has lawful guardian",
        text=(
            "(1) A Data Fiduciary, while obtaining verifiable consent from an individual identifying "
            "herself as the lawful guardian of a person with disability, shall observe due diligence "
            "to verify that such guardian is appointed by a court of law, or by a designated "
            "authority or by a local level committee, under the law applicable to guardianship. (2) "
            "In this rule, the expression— (a) “designated authority” shall mean an authority "
            "designated under section 15 of the Rights of Persons with Disabilities Act, 2016 (49 of "
            "2016) to support persons with disabilities in exercise of their legal capacity; (b) “law "
            "applicable to guardianship” shall mean, — (i) in relation to an individual who has long "
            "term physical, mental, intellectual or sensory impairment which, in interaction with "
            "barriers, hinders her full and effective participation in society equally with others "
            "and who despite being provided adequate and appropriate support is unable to take "
            "legally binding decisions, the provisions of law contained in Rights of Persons with "
            "Disabilities Act, 2016 (49 of 2016) and the rules made thereunder; and (ii) in relation "
            "to a person who is suffering from any of the conditions relating to autism, cerebral "
            "palsy, mental retardation or a combination of such conditions and includes a person "
            "suffering from severe multiple disability, the provisions of law of the National Trust "
            "for the Welfare of Persons with Autism, Cerebral Palsy, Mental Retardation and Multiple "
            "Disabilities Act, 1999 (44 of 1999) and the rules made thereunder; (c) “local level "
            "committee” shall mean a local level committee constituted under section 13 of the "
            "National Trust for the Welfare of Persons with Autism, Cerebral Palsy, Mental "
            "Retardation and Multiple Disabilities Act, 1999 (44 of 1999); (d) “person with "
            "disability” shall mean and include— (i) an individual who has long term physical, "
            "mental, intellectual or sensory impairment which, in interaction with barriers, hinders "
            "her full and effective participation in society equally with others and who, despite "
            "being provided adequate and appropriate support, is unable to take legally binding "
            "decisions; and (ii) an individual who is suffering from any of the conditions relating "
            "to autism, cerebral palsy, mental retardation or a combination of any two or more of "
            "such conditions and includes an individual suffering from severe multiple disability and "
            "who, despite being provided adequate and appropriate support, is unable to take legally "
            "binding decisions."
        ),
    ),
    RuleText(
        section_id="rule_12",
        number=12,
        title="Exemptions from certain obligations applicable to processing of personal data of child",
        text=(
            "(1) The provisions of sub-sections (1) and (3) of section 9 of the Act shall not be "
            "applicable to processing of personal data of a child by such class of Data Fiduciaries "
            "as are specified in Part A of Fourth Schedule, subject to such conditions as are "
            "specified in the said Part. (2) The provisions of sub-sections (1) and (3) of section 9 "
            "of the Act shall not be applicable to processing of personal data of a child for such "
            "purposes as are specified in Part B of Fourth Schedule, subject to such conditions as "
            "are specified in the said Part."
        ),
    ),
    RuleText(
        section_id="rule_13",
        number=13,
        title="Additional obligations of Significant Data Fiduciary",
        text=(
            "(1) A Significant Data Fiduciary shall, once in every period of twelve months from the "
            "date on which it is notified as such or is included in the class of Data Fiduciaries "
            "notified as such, undertake a Data Protection Impact Assessment and an audit to ensure "
            "effective observance of the provisions of this Act and the rules made thereunder. (2) A "
            "Significant Data Fiduciary shall cause the person carrying out the Data Protection "
            "Impact Assessment and audit to furnish to the Board a report containing significant "
            "observations in the Data Protection Impact Assessment and audit. (3) A Significant Data "
            "Fiduciary shall observe due diligence to verify that technical measures including "
            "algorithmic software adopted by it for hosting, display, uploading, modification, "
            "publishing, transmission, storage, updating or sharing of personal data processed by it "
            "are not likely to pose a risk to the rights of Data Principals. (4) A Significant Data "
            "Fiduciary shall undertake measures to ensure that personal data specified by the Central "
            "Government, on the basis of the recommendations of a committee constituted by it, is "
            "processed subject to the restriction that the personal data and the traffic data "
            "pertaining to its flow is not transferred outside the territory of India. (5) In this "
            "rule, “committee” means a committee constituted by the Central Government for the "
            "purpose of this rule, which shall include officials from the Ministry of Electronics and "
            "Technology and may include officials from other Ministries or Department of the Central "
            "Government."
        ),
    ),
    RuleText(
        section_id="rule_14",
        number=14,
        title="Rights of Data Principals",
        text=(
            "(1) For enabling Data Principals to exercise their rights under the Act, the Data "
            "Fiduciary and, where applicable, the Consent Manager, shall prominently publish on its "
            "website or app, or both, as the case may be, — (a) the details of the means using which "
            "a Data Principal may make a request for the exercise of such rights; and (b) the "
            "particulars, if any, such as the username or other identifier of such a Data Principal, "
            "which may be required to identify her under its terms of service. (2) To exercise the "
            "rights of the Data Principal under the Act, she may make a request to the Data Fiduciary "
            "to whom she has previously given consent for processing of her personal data, using the "
            "means and furnishing the particulars required by such Data Fiduciary for the exercise of "
            "such rights. (3) Every Data Fiduciary and Consent Manager shall prominently publish on "
            "its website or app, or both, as the case may be, within a reasonable period not "
            "exceeding ninety days under its grievance redressal system for responding to the "
            "grievances of Data Principals and shall, for ensuring the effectiveness of the system in "
            "responding within such period, implement appropriate technical and organisational "
            "measures. (4) To exercise the rights of the Data Principal under the Act, she may, in "
            "accordance with the terms of service of the Data Fiduciary and such law as may be "
            "applicable, nominate one or more individuals, using the means and furnishing the "
            "particulars required by such Data Fiduciary for the exercise of such right. (5) In this "
            "rule, the expression “identifier” shall mean any sequence of characters issued by the "
            "Data Fiduciary to identify the Data Principal and includes a customer identification "
            "file number, customer acquisition form number, application reference number, enrolment "
            "ID, email address, mobile number or licence number that enables such identification."
        ),
    ),
    RuleText(
        section_id="rule_15",
        number=15,
        title="Transfer of personal data outside the territory of India",
        text=(
            "Any personal data processed by a Data Fiduciary under the Act may be transferred outside "
            "the territory of India subject to the restriction that the Data Fiduciary shall meet "
            "such requirements as the Central Government may, by general or special order, specify in "
            "respect of making such personal data available to any foreign State, or to any person or "
            "entity under the control of or any agency of such a State."
        ),
    ),
    RuleText(
        section_id="rule_16",
        number=16,
        title="Exemption from Act for research, archiving or statistical purposes",
        text=(
            "The provisions of the Act shall not apply to the processing of personal data necessary "
            "for research, archiving or statistical purposes if it is carried on in accordance with "
            "the standards specified in Second Schedule."
        ),
    ),
    RuleText(
        section_id="rule_17",
        number=17,
        title="Appointment of Chairperson and other Members",
        text=(
            "(1) The Central Government shall constitute a Search-cum-Selection Committee, with the "
            "Cabinet Secretary as the chairperson and the Secretaries to the Government of India in "
            "charge of the Department of Legal Affairs and the Ministry of Electronics and "
            "Information Technology and two experts of repute having special knowledge or practical "
            "experience in a field which in the opinion of the Central Government may be useful to "
            "the Board as members, to recommend individuals for appointment as Chairperson. (2) The "
            "Central Government shall constitute a Search-cum-Selection Committee, with the Secretary "
            "to the Government of India in the Ministry of Electronics and Information Technology as "
            "the chairperson and the Secretary to the Government of India in charge of the Department "
            "of Legal Affairs, and two experts of repute having special knowledge or practical "
            "experience in a field which in the opinion of the Central Government may be useful to "
            "the Board as members, to recommend individuals for appointment as a Member other than "
            "the Chairperson. (3) The Central Government shall, after considering the suitability of "
            "individuals recommended by the Search-cum-Selection Committee, appoint the Chairperson "
            "or other Member, as the case may be. (4) No act or proceeding of the "
            "Search-cum-Selection Committee specified in sub-rules (1) and (2) of this rule shall be "
            "called in question on the ground merely of the existence of any vacancy or absences in "
            "such committee or defect in its constitution."
        ),
    ),
    RuleText(
        section_id="rule_18",
        number=18,
        title="Salary, allowances and other terms and conditions of service of Chairperson and other Members",
        text=(
            "The Chairperson and every other Member shall receive such salary and allowances and "
            "shall have such other terms and conditions of service as are specified in Fifth "
            "Schedule."
        ),
    ),
    RuleText(
        section_id="rule_19",
        number=19,
        title="Procedure for meetings of Board and authentication of its orders, directions and instruments",
        text=(
            "(1) The Chairperson shall fix the date, time and place of meetings of the Board, approve "
            "the items of agenda therefor, and cause notice specifying the same to be issued under "
            "her signature or that of such other individual as the Chairperson may authorise by "
            "general or special order in writing. (2) Meetings of the Board shall be chaired by the "
            "Chairperson and, in her absence, by such other Member as the Members present at the "
            "meeting may choose from amongst themselves. (3) One-third of the membership of the Board "
            "shall be the quorum for its meetings. (4) All questions which come up before any meeting "
            "of the Board shall be decided by a majority of the votes of Members present and voting, "
            "and, in the event of an equality of votes, the Chairperson, or in her absence, the "
            "person chairing, shall have a second or casting vote. (5) If a Member has an interest in "
            "any item of business to be transacted at a meeting of the Board, she shall not "
            "participate in or vote on the same and, in such a case, the decision on such item shall "
            "be taken by a majority of the votes of other Members present and voting. (6) In case an "
            "emergent situation warrants immediate action by the Board and it is not feasible to call "
            "a meeting of the Board, the Chairperson may, while recording the reasons in writing, "
            "take such action as may be necessary, which shall be communicated within seven days to "
            "all Members and laid before the Board for ratification at its next meeting. (7) If the "
            "Chairperson so directs, an item of business or issue which requires decision of the "
            "Board may be referred to Members by circulation and such item may be decided with the "
            "approval of majority of the Members. (8) The Chairperson or any Member of the Board, or "
            "any individual authorised by it,by a general or special order in writing, may, under her "
            "signature, authenticate its order, direction or instrument. (9) The inquiry by the Board "
            "shall be completed within a period of six months from the date of receipt of the "
            "intimation, complaint, reference or direction under section 27 of the Act, unless such "
            "period is extended by it, for reasons to be recorded in writing, for a further period "
            "not exceeding three months at a time."
        ),
    ),
    RuleText(
        section_id="rule_20",
        number=20,
        title="Functioning of Board as digital office",
        text=(
            "The Board shall function as a digital office, without prejudice to its power to summon "
            "and enforce the attendance of any person and examine her on oath, may adopt techno-legal "
            "measures to conduct proceedings in a manner that does not require physical presence of "
            "any individual."
        ),
    ),
    RuleText(
        section_id="rule_21",
        number=21,
        title="Terms and conditions of appointment and service of officers and employees of Board",
        text=(
            "(1) The Board may, with previous approval of the Central Government, appoint such "
            "officers and employees as it may deem necessary for the efficient discharge of its "
            "functions under the provisions of the Act. (2) The terms and conditions of service of "
            "officers and employees of the Board shall be such as are specified in Sixth Schedule."
        ),
    ),
    RuleText(
        section_id="rule_22",
        number=22,
        title="Appeal to Appellate Tribunal",
        text=(
            "(1) Any person aggrieved by an order or direction of the Board, may prefer an appeal "
            "before the Appellate Tribunal, it shall be filed in digital form as the Appellate "
            "Tribunal may decide. (2) An appeal filed with the Appellate Tribunal shall be "
            "accompanied by fee of like amount as is applicable in respect of an appeal filed under "
            "the Telecom Regulatory Authority of India Act, 1997 (24 of 1997), unless reduced or "
            "waived by the Chairperson of the Appellate Tribunal at her discretion, and the same "
            "shall be payable digitally using the Unified Payments Interface or such other payment "
            "system authorised by the Reserve Bank of India. (3) The Appellate Tribunal— (a) shall "
            "not be bound by the procedure laid down by the Code of Civil Procedure, 1908 (5 of "
            "1908), but shall be guided by the principles of natural justice and, subject to the "
            "provisions of the Act, may regulate its own procedure; and (b) shall function as a "
            "digital office which, without prejudice to its power to summon and enforce the "
            "attendance of any person and examine her on oath, may adopt techno-legal measures to "
            "conduct proceedings in a manner that does not require physical presence of any "
            "individual."
        ),
    ),
    RuleText(
        section_id="rule_23",
        number=23,
        title="Calling for information from Data Fiduciary or intermediary",
        text=(
            "(1) The Central Government may, for such purposes of the Act as are specified in Seventh "
            "Schedule, acting through the corresponding authorised person specified in the said "
            "Schedule, require any Data Fiduciary or intermediary to furnish such information as may "
            "be called for, within the specified period as may be given in such. (2) Where the "
            "disclosure of furnishing of information as referred to in sub-rule (1) is likely to "
            "prejudicially affect the sovereignty and integrity of India or security of the State, "
            "the Central Government may require the Data Fiduciary or intermediary to not disclose "
            "such furnishing to affected Data Principal or any other person except with the previous "
            "permission, in writing, of the authorised person. (3) For the purposes of this rule, the "
            "expression “intermediary” shall have the same meaning as assigned to it in the "
            "Information Technology Act, 2000 (21 of 2000)."
        ),
    ),
]


_BY_ID: dict[str, RuleText] = {r.section_id: r for r in RULES}


def by_id(section_id: str) -> RuleText | None:
    """Look up one rule by its canonical id, for example "rule_6"."""
    return _BY_ID.get(section_id)
