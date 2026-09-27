"""DPDP Act 2023 statutory text.  OWNER: Prerana

Typed out as structured Python data, not scraped or PDF-extracted. Three reasons
worth stating to the jury: no parsing errors in legal text, no dependency on a
government site being up during the demo, and every character is reviewable in
the diff.

SOURCE OF TEXT (verbatim, no paraphrase):
    The Digital Personal Data Protection Act, 2023 (No. 22 of 2023), as
    published in the Gazette of India, Extraordinary, Part II, Section 1,
    No. 25, New Delhi, Friday, August 11, 2023.
    URL: https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf
    Retrieved: 2026-09-26.

Every `text` value below is a literal slice of that gazette, including its
illustrations, its punctuation and its em dashes. Nothing is summarised and
nothing is reworded. If a provision could not be sourced it was left out rather
than approximated.

GRANULARITY NOTE: section 8 and section 10 are stored one sub-section per
entry, because the rules engine cites them that way (r06_security cites s.8(5),
r07_breach cites s.8(6), retention cites s.8(7), r12_verification cites s.8(1),
r08_dpia cites s.10(2)). Sections cited as a whole are stored whole. A checker
whose DPDP_SECTION is a bare "s.10" should therefore list both "s.10(1)" and
"s.10(2)" in its RETRIEVAL_SECTION_IDS, since no bare "s.10" row exists.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ActSection:
    section_id: str
    title: str
    text: str

    @property
    def citation_label(self) -> str:
        number = self.section_id.removeprefix("s.")
        return f"DPDP Act 2023, Section {number}"


ACT_SECTIONS: list[ActSection] = [
    ActSection(
        section_id="s.2(i)",
        title="Definition of Data Fiduciary",
        text=(
            "(i) “Data Fiduciary” means any person who alone or in conjunction with other persons "
            "determines the purpose and means of processing of personal data;"
        ),
    ),
    ActSection(
        section_id="s.2(j)",
        title="Definition of Data Principal",
        text=(
            "(j) “Data Principal” means the individual to whom the personal data relates and where "
            "such individual is— (i) a child, includes the parents or lawful guardian of such a "
            "child; (ii) a person with disability, includes her lawful guardian, acting on her "
            "behalf;"
        ),
    ),
    ActSection(
        section_id="s.2(t)",
        title="Definition of personal data",
        text=(
            "(t) “personal data” means any data about an individual who is identifiable by or in "
            "relation to such data;"
        ),
    ),
    ActSection(
        section_id="s.2(u)",
        title="Definition of personal data breach",
        text=(
            "(u) “personal data breach” means any unauthorised processing of personal data or "
            "accidental disclosure, acquisition, sharing, use, alteration, destruction or loss of "
            "access to personal data, that compromises the confidentiality, integrity or availability "
            "of personal data;"
        ),
    ),
    ActSection(
        section_id="s.2(x)",
        title="Definition of processing",
        text=(
            "(x) “processing” in relation to personal data, means a wholly or partly automated "
            "operation or set of operations performed on digital personal data, and includes "
            "operations such as collection, recording, organisation, structuring, storage, "
            "adaptation, retrieval, use, alignment or combination, indexing, sharing, disclosure by "
            "transmission, dissemination or otherwise making available, restriction, erasure or "
            "destruction;"
        ),
    ),
    ActSection(
        section_id="s.2(f)",
        title="Definition of child",
        text=(
            "(f) “child” means an individual who has not completed the age of eighteen years;"
        ),
    ),
    ActSection(
        section_id="s.2(z)",
        title="Definition of Significant Data Fiduciary",
        text=(
            "(z) “Significant Data Fiduciary” means any Data Fiduciary or class of Data Fiduciaries "
            "as may be notified by the Central Government under section 10;"
        ),
    ),
    ActSection(
        section_id="s.5",
        title="Notice",
        text=(
            "(1) Every request made to a Data Principal under section 6 for consent shall be "
            "accompanied or preceded by a notice given by the Data Fiduciary to the Data Principal, "
            "informing her,— (i) the personal data and the purpose for which the same is proposed to "
            "be processed; (ii) the manner in which she may exercise her rights under sub-section (4) "
            "of section 6 and section 13; and (iii) the manner in which the Data Principal may make a "
            "complaint to the Board, in such manner and as may be prescribed. Illustration. X, an "
            "individual, opens a bank account using the mobile app or website of Y, a bank. To "
            "complete the Know-Your-Customer requirements under law for opening of bank account, X "
            "opts for processing of her personal data by Y in a live, video-based customer "
            "identification process. Y shall accompany or precede the request for the personal data "
            "with notice to X, describing the personal data and the purpose of its processing. (2) "
            "Where a Data Principal has given her consent for the processing of her personal data "
            "before the date of commencement of this Act,— (a) the Data Fiduciary shall, as soon as "
            "it is reasonably practicable, give to the Data Principal a notice informing her,–– (i) "
            "the personal data and the purpose for which the same has been processed; (ii) the manner "
            "in which she may exercise her rights under sub-section (4) of section 6 and section 13; "
            "and (iii) the manner in which the Data Principal may make a complaint to the Board, in "
            "such manner and as may be prescribed. (b) the Data Fiduciary may continue to process the "
            "personal data until and unless the Data Principal withdraws her consent. Illustration. "
            "X, an individual, gave her consent to the processing of her personal data for an online "
            "shopping app or website operated by Y, an e-commerce service provider, before the "
            "commencement of this Act. Upon commencement of the Act, Y shall, as soon as practicable, "
            "give through email, in-app notification or other effective method information to X, "
            "describing the personal data and the purpose of its processing. (3) The Data Fiduciary "
            "shall give the Data Principal the option to access the contents of the notice referred "
            "to in sub-sections (1) and (2) in English or any language specified in the Eighth "
            "Schedule to the Constitution."
        ),
    ),
    ActSection(
        section_id="s.6",
        title="Consent",
        text=(
            "(1) The consent given by the Data Principal shall be free, specific, informed, "
            "unconditional and unambiguous with a clear affirmative action, and shall signify an "
            "agreement to the processing of her personal data for the specified purpose and be "
            "limited to such personal data as is necessary for such specified purpose. Illustration. "
            "X, an individual, downloads Y, a telemedicine app. Y requests the consent of X for (i) "
            "the processing of her personal data for making available telemedicine services, and (ii) "
            "accessing her mobile phone contact list, and X signifies her consent to both. Since "
            "phone contact list is not necessary for making available telemedicine services, her "
            "consent shall be limited to the processing of her personal data for making available "
            "telemedicine services. (2) Any part of consent referred in sub-section (1) which "
            "constitutes an infringement of the provisions of this Act or the rules made thereunder "
            "or any other law for the time being in force shall be invalid to the extent of such "
            "infringement. Illustration. X, an individual, buys an insurance policy using the mobile "
            "app or website of Y, an insurer. She gives to Y her consent for (i) the processing of "
            "her personal data by Y for the purpose of issuing the policy, and (ii) waiving her right "
            "to file a complaint to the Data Protection Board of India. Part (ii) of the consent, "
            "relating to waiver of her right to file a complaint, shall be invalid. (3) Every request "
            "for consent under the provisions of this Act or the rules made thereunder shall be "
            "presented to the Data Principal in a clear and plain language, giving her the option to "
            "access such request in English or any language specified in the Eighth Schedule to the "
            "Constitution and providing the contact details of a Data Protection Officer, where "
            "applicable, or of any other person authorised by the Data Fiduciary to respond to any "
            "communication from the Data Principal for the purpose of exercise of her rights under "
            "the provisions of this Act. (4) Where consent given by the Data Principal is the basis "
            "of processing of personal data, such Data Principal shall have the right to withdraw her "
            "consent at any time, with the ease of doing so being comparable to the ease with which "
            "such consent was given. (5) The consequences of the withdrawal referred to in "
            "sub-section (4) shall be borne by the Data Principal, and such withdrawal shall not "
            "affect the legality of processing of the personal data based on consent before its "
            "withdrawal. Illustration. X, an individual, is the user of an online shopping app or "
            "website operated by Y, an e-commerce service provider. X consents to the processing of "
            "her personal data by Y for the purpose of fulfilling her supply order and places an "
            "order for supply of a good while making payment for the same. If X withdraws her "
            "consent, Y may stop enabling X to use the app or website for placing orders, but may not "
            "stop the processing for supply of the goods already ordered and paid for by X. (6) If a "
            "Data Principal withdraws her consent to the processing of personal data under "
            "sub-section (5), the Data Fiduciary shall, within a reasonable time, cease and cause its "
            "Data Processors to cease processing the personal data of such Data Principal unless such "
            "processing without her consent is required or authorised under the provisions of this "
            "Act or the rules made thereunder or any other law for the time being in force in India. "
            "Illustration. X, a telecom service provider, enters into a contract with Y, a Data "
            "Processor, for emailing telephone bills to the customers of X. Z, a customer of X, who "
            "had earlier given her consent to X for the processing of her personal data for emailing "
            "of bills, downloads the mobile app of X and opts to receive bills only on the app. X "
            "shall itself cease, and shall cause Y to cease, the processing of the personal data of Z "
            "for emailing bills. (7) The Data Principal may give, manage, review or withdraw her "
            "consent to the Data Fiduciary through a Consent Manager. (8) The Consent Manager shall "
            "be accountable to the Data Principal and shall act on her behalf in such manner and "
            "subject to such obligations as may be prescribed. (9) Every Consent Manager shall be "
            "registered with the Board in such manner and subject to such technical, operational, "
            "financial and other conditions as may be prescribed. (10) Where a consent given by the "
            "Data Principal is the basis of processing of personal data and a question arises in this "
            "regard in a proceeding, the Data Fiduciary shall be obliged to prove that a notice was "
            "given by her to the Data Principal and consent was given by such Data Principal to the "
            "Data Fiduciary in accordance with the provisions of this Act and the rules made "
            "thereunder."
        ),
    ),
    ActSection(
        section_id="s.7",
        title="Certain legitimate uses",
        text=(
            "A Data Fiduciary may process personal data of a Data Principal for any of following "
            "uses, namely:— (a) for the specified purpose for which the Data Principal has "
            "voluntarily provided her personal data to the Data Fiduciary, and in respect of which "
            "she has not indicated to the Data Fiduciary that she does not consent to the use of her "
            "personal Illustrations. (I) X, an individual, makes a purchase at Y, a pharmacy. She "
            "voluntarily provides Y her personal data and requests Y to acknowledge receipt of the "
            "payment made for the purchase by sending a message to her mobile phone. Y may process "
            "the personal data of X for the purpose of sending the receipt. (II) X, an individual, "
            "electronically messages Y, a real estate broker, requesting Y to help identify a "
            "suitable rented accommodation for her and shares her personal data for this purpose. Y "
            "may process her personal data to identify and intimate to her the details of "
            "accommodation available on rent. Subsequently, X informs Y that X no longer needs help "
            "from Y. Y shall cease to process the personal data of X; (b) for the State and any of "
            "its instrumentalities to provide or issue to the Data Principal such subsidy, benefit, "
            "service, certificate, licence or permit as may be prescribed, where–– (i) she has "
            "previously consented to the processing of her personal data by the State or any of its "
            "instrumentalities for any subsidy, benefit, service, certificate, licence or permit; or "
            "(ii) such personal data is available in digital form in, or in non-digital form and "
            "digitised subsequently from, any database, register, book or other document which is "
            "maintained by the State or any of its instrumentalities and is notified by the Central "
            "Government, subject to standards followed for processing being in accordance with the "
            "policy issued by the Central Government or any law for the time being in force for "
            "governance of personal data. Illustration. X. a pregnant woman, enrols herself on an app "
            "or website to avail of government’s maternity benefits programme, while consenting to "
            "provide her personal data for the purpose of availing of such benefits. Government may "
            "process the personal data of X processing to determine her eligibility to receive any "
            "other prescribed benefit from the government; (c) for the performance by the State or "
            "any of its instrumentalities of any function under any law for the time being in force "
            "in India or in the interest of sovereignty and integrity of India or security of the "
            "State; (d) for fulfilling any obligation under any law for the time being in force in "
            "India on any person to disclose any information to the State or any of its "
            "instrumentalities, subject to such processing being in accordance with the provisions "
            "regarding disclosure of such information in any other law for the time being in force; "
            "(e) for compliance with any judgment or decree or order issued under any law for the "
            "time being in force in India, or any judgment or order relating to claims of a "
            "contractual or civil nature under any law for the time being in force outside India; (f) "
            "for responding to a medical emergency involving a threat to the life or immediate threat "
            "to the health of the Data Principal or any other individual; (g) for taking measures to "
            "provide medical treatment or health services to any individual during an epidemic, "
            "outbreak of disease, or any other threat to public health; (h) for taking measures to "
            "ensure safety of, or provide assistance or services to, any individual during any "
            "disaster, or any breakdown of public order. Explanation.—For the purposes of this "
            "clause, the expression “disaster” shall have the same meaning as assigned to it in "
            "clause (d) of section 2 of the Disaster Management Act, 2005; or (i) for the purposes of "
            "employment or those related to safeguarding the employer from loss or liability, such as "
            "prevention of corporate espionage, maintenance of confidentiality of trade secrets, "
            "intellectual property, classified information or provision of any service or benefit "
            "sought by a Data Principal who is an employee."
        ),
    ),
    ActSection(
        section_id="s.8(1)",
        title="General obligations of Data Fiduciary (sub-section (1))",
        text=(
            "(1) A Data Fiduciary shall, irrespective of any agreement to the contrary or failure of "
            "a Data Principal to carry out the duties provided under this Act, be responsible for "
            "complying with the provisions of this Act and the rules made thereunder in respect of "
            "any processing undertaken by it or on its behalf by a Data Processor."
        ),
    ),
    ActSection(
        section_id="s.8(2)",
        title="General obligations of Data Fiduciary (sub-section (2))",
        text=(
            "(2) A Data Fiduciary may engage, appoint, use or otherwise involve a Data Processor to "
            "process personal data on its behalf for any activity related to offering of goods or "
            "services to Data Principals only under a valid contract."
        ),
    ),
    ActSection(
        section_id="s.8(3)",
        title="General obligations of Data Fiduciary (sub-section (3))",
        text=(
            "(3) Where personal data processed by a Data Fiduciary is likely to be— (a) used to make "
            "a decision that affects the Data Principal; or (b) disclosed to another Data Fiduciary, "
            "the Data Fiduciary processing such personal data shall ensure its completeness, accuracy "
            "and consistency."
        ),
    ),
    ActSection(
        section_id="s.8(4)",
        title="General obligations of Data Fiduciary (sub-section (4))",
        text=(
            "(4) A Data Fiduciary shall implement appropriate technical and organisational measures "
            "to ensure effective observance of the provisions of this Act and the rules made "
            "thereunder."
        ),
    ),
    ActSection(
        section_id="s.8(5)",
        title="General obligations of Data Fiduciary (sub-section (5))",
        text=(
            "(5) A Data Fiduciary shall protect personal data in its possession or under its control, "
            "including in respect of any processing undertaken by it or on its behalf by a Data "
            "Processor, by taking reasonable security safeguards to prevent personal data breach."
        ),
    ),
    ActSection(
        section_id="s.8(6)",
        title="General obligations of Data Fiduciary (sub-section (6))",
        text=(
            "(6) In the event of a personal data breach, the Data Fiduciary shall give the Board and "
            "each affected Data Principal, intimation of such breach in such form and manner as may "
            "be prescribed."
        ),
    ),
    ActSection(
        section_id="s.8(7)",
        title="General obligations of Data Fiduciary (sub-section (7))",
        text=(
            "(7) A Data Fiduciary shall, unless retention is necessary for compliance with any law "
            "for the time being in force,— (a) erase personal data, upon the Data Principal "
            "withdrawing her consent or as soon as it is reasonable to assume that the specified "
            "purpose is no longer being served, whichever is earlier; and (b) cause its Data "
            "Processor to erase any personal data that was made available by the Data Fiduciary for "
            "processing to such Data Processor. Illustrations. (I) X, an individual, registers "
            "herself on an online marketplace operated by Y, an e-commerce service provider. X gives "
            "her consent to Y for the processing of her personal data for selling her used car. The "
            "online marketplace helps conclude the sale. Y shall no longer retain her personal data. "
            "(II) X, an individual, decides to close her savings account with Y, a bank. Y is "
            "required by law applicable to banks to maintain the record of the identity of its "
            "clients for a period of ten years beyond closing of accounts. Since retention is "
            "necessary for compliance with law, Y shall retain X’s personal data for the said period."
        ),
    ),
    ActSection(
        section_id="s.8(8)",
        title="General obligations of Data Fiduciary (sub-section (8))",
        text=(
            "(8) The purpose referred to in clause (a) of sub-section (7) shall be deemed to no "
            "longer be served, if the Data Principal does not–– (a) approach the Data Fiduciary for "
            "the performance of the specified purpose; and (b) exercise any of her rights in relation "
            "to such processing, for such time period as may be prescribed, and different time "
            "periods may be prescribed for different classes of Data Fiduciaries and for different "
            "purposes."
        ),
    ),
    ActSection(
        section_id="s.8(9)",
        title="General obligations of Data Fiduciary (sub-section (9))",
        text=(
            "(9) A Data Fiduciary shall publish, in such manner as may be prescribed, the business "
            "contact information of a Data Protection Officer, if applicable, or a person who is able "
            "to answer on behalf of the Data Fiduciary, the questions, if any, raised by the Data "
            "Principal about the processing of her personal data."
        ),
    ),
    ActSection(
        section_id="s.8(10)",
        title="General obligations of Data Fiduciary (sub-section (10))",
        text=(
            "(10) A Data Fiduciary shall establish an effective mechanism to redress the grievances "
            "of Data Principals."
        ),
    ),
    ActSection(
        section_id="s.8(11)",
        title="General obligations of Data Fiduciary (sub-section (11))",
        text=(
            "(11) For the purposes of this section, it is hereby clarified that a Data Principal "
            "shall be considered as not having approached the Data Fiduciary for the performance of "
            "the specified purpose, in any period during which she has not initiated contact with the "
            "Data Fiduciary for such performance, in person or by way of communication in electronic "
            "or physical form."
        ),
    ),
    ActSection(
        section_id="s.9",
        title="Processing of personal data of children",
        text=(
            "(1) The Data Fiduciary shall, before processing any personal data of a child or a person "
            "with disability who has a lawful guardian obtain verifiable consent of the parent of "
            "such child or the lawful guardian, as the case may be, in such manner as may be "
            "prescribed. Explanation.—For the purpose of this sub-section, the expression “consent of "
            "the parent” includes the consent of lawful guardian, wherever applicable. (2) A Data "
            "Fiduciary shall not undertake such processing of personal data that is likely to cause "
            "any detrimental effect on the well-being of a child. (3) A Data Fiduciary shall not "
            "undertake tracking or behavioural monitoring of children or targeted advertising "
            "directed at children. (4) The provisions of sub-sections (1) and (3) shall not be "
            "applicable to processing of personal data of a child by such classes of Data Fiduciaries "
            "or for such purposes, and subject to such conditions, as may be prescribed. (5) The "
            "Central Government may, if satisfied that a Data Fiduciary has ensured that its "
            "processing of personal data of children is done in a manner that is verifiably safe, "
            "notify for such processing by such Data Fiduciary the age above which that Data "
            "Fiduciary shall be exempt from the applicability of all or any of the obligations under "
            "sub-sections (1) and (3) in respect of processing by that Data Fiduciary as the "
            "notification may specify."
        ),
    ),
    ActSection(
        section_id="s.10(1)",
        title="Additional obligations of Significant Data Fiduciary (sub-section (1))",
        text=(
            "(1) The Central Government may notify any Data Fiduciary or class of Data Fiduciaries as "
            "Significant Data Fiduciary, on the basis of an assessment of such relevant factors as it "
            "may determine, including— (a) the volume and sensitivity of personal data processed; (b) "
            "risk to the rights of Data Principal; (c) potential impact on the sovereignty and "
            "integrity of India; (d) risk to electoral democracy; (e) security of the State; and (f) "
            "public order."
        ),
    ),
    ActSection(
        section_id="s.10(2)",
        title="Additional obligations of Significant Data Fiduciary (sub-section (2))",
        text=(
            "(2) The Significant Data Fiduciary shall— (a) appoint a Data Protection Officer who "
            "shall— (i) represent the Significant Data Fiduciary under the provisions of this Act; "
            "(ii) be based in India; (iii) be an individual responsible to the Board of Directors or "
            "similar governing body of the Significant Data Fiduciary; and (iv) be the point of "
            "contact for the grievance redressal mechanism under the provisions of this Act; (b) "
            "appoint an independent data auditor to carry out data audit, who shall evaluate the "
            "compliance of the Significant Data Fiduciary in accordance with the provisions of this "
            "Act; and (c) undertake the following other measures, namely:— (i) periodic Data "
            "Protection Impact Assessment, which shall be a process comprising a description of the "
            "rights of Data Principals and the purpose of processing of their personal data, "
            "assessment and management of the risk to the rights of the Data Principals, and such "
            "other matters regarding such process as may be prescribed; (ii) periodic audit; and "
            "(iii) such other measures, consistent with the provisions of this Act, as may be "
            "prescribed."
        ),
    ),
    ActSection(
        section_id="s.11",
        title="Right to access information about personal data",
        text=(
            "(1) The Data Principal shall have the right to obtain from the Data Fiduciary to whom "
            "she has previously given consent, including consent as referred to in clause (a) of "
            "section 7 (hereinafter referred to as the said Data Fiduciary), for processing of "
            "personal data, upon making to it a request in such manner as may be prescribed,— (a) a "
            "summary of personal data which is being processed by such Data Fiduciary and the "
            "processing activities undertaken by that Data Fiduciary with respect to such personal "
            "data; (b) the identities of all other Data Fiduciaries and Data Processors with whom the "
            "personal data has been shared by such Data Fiduciary, along with a description of the "
            "personal data so shared; and (c) any other information related to the personal data of "
            "such Data Principal and its processing, as may be prescribed. (2) Nothing contained in "
            "clause (b) or clause (c) of sub-section (1) shall apply in respect of the sharing of any "
            "personal data by the said Data Fiduciary with any other Data Fiduciary authorised by law "
            "to obtain such personal data, where such sharing is pursuant to a request made in "
            "writing by such other Data Fiduciary for the purpose of prevention or detection or "
            "investigation of offences or cyber incidents, or for prosecution or punishment of "
            "offences."
        ),
    ),
    ActSection(
        section_id="s.12",
        title="Right to correction and erasure of personal data",
        text=(
            "(1) A Data Principal shall have the right to correction, completion, updating and "
            "erasure of her personal data for the processing of which she has previously given "
            "consent, including consent as referred to in clause (a) of section 7, in accordance with "
            "any requirement or procedure under any law for the time being in force. (2) A Data "
            "Fiduciary shall, upon receiving a request for correction, completion or updating from a "
            "Data Principal,— (a) correct the inaccurate or misleading personal data; (b) complete "
            "the incomplete personal data; and (c) update the personal data. (3) A Data Principal "
            "shall make a request in such manner as may be prescribed to the Data Fiduciary for "
            "erasure of her personal data, and upon receipt of such a request, the Data Fiduciary "
            "shall erase her personal data unless retention of the same is necessary for the "
            "specified purpose or for compliance with any law for the time being in force."
        ),
    ),
    ActSection(
        section_id="s.13",
        title="Right of grievance redressal",
        text=(
            "(1) A Data Principal shall have the right to have readily available means of grievance "
            "redressal provided by a Data Fiduciary or Consent Manager in respect of any act or "
            "omission of such Data Fiduciary or Consent Manager regarding the performance of its "
            "obligations in relation to the personal data of such Data Principal or the exercise of "
            "her rights under the provisions of this Act and the rules made thereunder. (2) The Data "
            "Fiduciary or Consent Manager shall respond to any grievances referred to in sub-section "
            "(1) within such period as may be prescribed from the date of its receipt for all or any "
            "class of Data Fiduciaries. (3) The Data Principal shall exhaust the opportunity of "
            "redressing her grievance under this section before approaching the Board."
        ),
    ),
    ActSection(
        section_id="s.14",
        title="Right to nominate",
        text=(
            "(1) A Data Principal shall have the right to nominate, in such manner as may be "
            "prescribed, any other individual, who shall, in the event of death or incapacity of the "
            "Data Principal, exercise the rights of the Data Principal in accordance with the "
            "provisions of this Act and the rules made thereunder. (2) For the purposes of this "
            "section, the expression “incapacity” means inability to exercise the rights of the Data "
            "Principal under the provisions of this Act or the rules made thereunder due to "
            "unsoundness of mind or infirmity of body."
        ),
    ),
    ActSection(
        section_id="s.27",
        title="Powers and functions of Board",
        text=(
            "(1) The Board shall exercise and perform the following powers and functions, namely:— "
            "(a) on receipt of an intimation of personal data breach under sub-section (6) of section "
            "8, to direct any urgent remedial or mitigation measures in the event of a personal data "
            "breach, and to inquire into such personal data breach and impose penalty as provided in "
            "this Act; (b) on a complaint made by a Data Principal in respect of a personal data "
            "breach or a breach in observance by a Data Fiduciary of its obligations in relation to "
            "her personal data or the exercise of her rights under the provisions of this Act, or on "
            "a reference made to it by the Central Government or a State Government, or in compliance "
            "of the directions of any court, to inquire into such breach and impose penalty as "
            "provided in this Act; (c) on a complaint made by a Data Principal in respect of a breach "
            "in observance by a Consent Manager of its obligations in relation to her personal data, "
            "to inquire into such breach and impose penalty as provided in this Act; (d) on receipt "
            "of an intimation of breach of any condition of registration of a Consent Manager, to "
            "inquire into such breach and impose penalty as provided in this Act; and (e) on a "
            "reference made by the Central Government in respect of the breach in observance of the "
            "provisions of sub-section (2) of section 37 by an intermediary, to inquire into such "
            "breach and impose penalty as provided in this Act. (2) The Board may, for the effective "
            "discharge of its functions under the provisions of this Act, after giving the person "
            "concerned an opportunity of being heard and after recording reasons in writing, issue "
            "such directions as it may consider necessary to such person, who shall be bound to "
            "comply with the same. (3) The Board may, on a representation made to it by a person "
            "affected by a direction issued under sub-section (1) or sub-section (2), or on a "
            "reference made by the Central Government, modify, suspend, withdraw or cancel such "
            "direction and, while doing so, impose such conditions as it may deem fit, subject to "
            "which the modification, suspension, withdrawal or cancellation shall have effect."
        ),
    ),
]


_BY_ID: dict[str, ActSection] = {s.section_id: s for s in ACT_SECTIONS}


def by_id(section_id: str) -> ActSection | None:
    """Look up one provision by its canonical id, for example "s.8(5)"."""
    return _BY_ID.get(section_id)
