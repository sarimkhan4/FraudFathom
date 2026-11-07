%  FraudFathom - Digital Fraud Detection Expert System

%  Architecture:
%    Layer 0: FACTS      - red flags the user observed
%    Layer 1: SIGNALS    - general fraud signals derived from facts
%    Layer 2: SCAM TYPES - scam(Type, RuleID) derived from signals
%    Layer 3: DECISION   - risk score, risk level, recommended actions

% ---------- Layer 0: facts the user can report (dynamic) ----------
:- dynamic asks_otp/0, asks_pin/0, asks_card_details/0, asks_cnic/0.
:- dynamic card_activation_request/0.
:- dynamic urgent_threat/0, asks_secrecy/0, emotional_request/0.
:- dynamic suspicious_link/0, shortened_link/0, fake_domain/0.
:- dynamic claims_bank/0, claims_government/0, claims_telecom/0, claims_courier/0.
:- dynamic asks_advance_fee/0, asks_wallet_transfer/0, wrong_transfer_claim/0.
:- dynamic asks_install_app/0, asks_remote_access/0.
:- dynamic personal_number_used/0, unknown_sender/0, spelling_errors/0.
:- dynamic prize_lottery/0, guaranteed_returns/0, too_good_salary/0.
:- dynamic marketplace_deal/0, romance_contact/0.
:- dynamic channel/1.   % call, sms, whatsapp, email, social_media, in_person

% ---------- Weights used for the risk score (data, not rules) ----------
weight(asks_otp, 5).            weight(asks_pin, 5).
weight(asks_card_details, 5).   weight(asks_cnic, 3).
weight(card_activation_request, 2).  
weight(urgent_threat, 3).       weight(asks_secrecy, 3).
weight(emotional_request, 2).   weight(suspicious_link, 3).
weight(shortened_link, 2).      weight(fake_domain, 4).
weight(claims_bank, 1).         weight(claims_government, 1).
weight(claims_telecom, 1).      weight(claims_courier, 1).
weight(asks_advance_fee, 4).    weight(asks_wallet_transfer, 3).
weight(wrong_transfer_claim, 3).
weight(asks_install_app, 4).
weight(asks_remote_access, 5).  weight(personal_number_used, 2).
weight(unknown_sender, 1).      weight(spelling_errors, 1).
weight(prize_lottery, 3).       weight(guaranteed_returns, 4).
weight(too_good_salary, 3).     weight(marketplace_deal, 1).
weight(romance_contact, 2).

% ---------- Plain-English description of each scam type ----------
describe(bank_impersonation, "Someone pretends to be your bank to steal credentials or money.").
describe(phishing_link, "A fake link/website is trying to steal your login or card data.").
describe(lottery_prize, "A fake prize/lottery that needs a fee or your personal data.").
describe(govt_aid_scam, "Fake government aid (e.g. BISP/Ehsaas style) to collect CNIC or money.").
describe(fake_officer_threat, "A fake officer threatens arrest/fines to extract money.").
describe(job_scam, "A fake job offer that asks for money or lures you via WhatsApp.").
describe(investment_scam, "Fake investment promising guaranteed returns (Ponzi/crypto style).").
describe(wallet_fraud, "Mobile-wallet fraud (JazzCash/Easypaisa style) - wrong transfer or PIN theft.").
describe(remote_access_scam, "Scammer wants control of your phone/PC to drain your accounts.").
describe(malicious_app, "You are being pushed to install a harmful app.").
describe(courier_scam, "Fake courier/parcel message asking for a fee or a link click.").
describe(family_emergency, "Fake emergency from a 'relative' asking for urgent money.").
describe(romance_scam, "Online relationship used to ask for money.").
describe(marketplace_scam, "Fake buyer/seller on marketplaces (e.g. OLX) trying to get your OTP or link click.").
describe(otp_theft, "Direct attempt to steal your One-Time Password.").
describe(credit_card_activation_fraud, "Scammer asks for a fee to activate a bank card and may steal your OTP or card details.").

%  Layer 1: SIGNAL RULES (26 rules)

% sensitive_info_request: they ask for OTP, PIN, card details or CNIC
sensitive_info_request :- asks_otp.
sensitive_info_request :- asks_pin.
sensitive_info_request :- asks_card_details.
sensitive_info_request :- asks_cnic.

% pressure_tactic: they rush or isolate you
pressure_tactic :- urgent_threat.
pressure_tactic :- asks_secrecy.
pressure_tactic :- emotional_request.

% unsafe_link: any dodgy link
unsafe_link :- suspicious_link.
unsafe_link :- shortened_link.
unsafe_link :- fake_domain.

% authority_impersonation: pretends to be someone official
authority_impersonation :- claims_bank.
authority_impersonation :- claims_government.
authority_impersonation :- claims_telecom.
authority_impersonation :- claims_courier.

% money_demand: they want money from you
money_demand :- asks_advance_fee.
money_demand :- asks_wallet_transfer.
money_demand :- wrong_transfer_claim.

% device_takeover: they want control of your device
device_takeover :- asks_install_app.
device_takeover :- asks_remote_access.

% unofficial_contact: official bodies do not contact like this
unofficial_contact :- personal_number_used.
unofficial_contact :- unknown_sender.

% reward_bait: too-good-to-be-true offers
reward_bait :- prize_lottery.
reward_bait :- guaranteed_returns.
reward_bait :- too_good_salary.

% sloppy_message: poor language quality
sloppy_message :- spelling_errors.

% credit_card_activation_attempt: payment requested to activate a bank card
credit_card_activation_attempt :- card_activation_request, asks_advance_fee.

%  Layer 2: SCAM-TYPE RULES (63 rules) - scam(Type, RuleID)

scam(bank_impersonation, s01) :- claims_bank, sensitive_info_request.
scam(bank_impersonation, s02) :- claims_bank, pressure_tactic, unsafe_link.
scam(phishing_link, s03) :- unsafe_link, sensitive_info_request.
scam(phishing_link, s04) :- fake_domain, authority_impersonation.
scam(lottery_prize, s05) :- prize_lottery, money_demand.
scam(lottery_prize, s06) :- prize_lottery, sensitive_info_request.
scam(govt_aid_scam, s07) :- claims_government, prize_lottery.
scam(govt_aid_scam, s08) :- claims_government, asks_cnic, channel(sms).
scam(fake_officer_threat, s09) :- claims_government, urgent_threat, money_demand.
scam(job_scam, s10) :- too_good_salary, asks_advance_fee.
scam(job_scam, s11) :- too_good_salary, channel(whatsapp), unknown_sender.
scam(investment_scam, s12) :- guaranteed_returns, unknown_sender.
scam(investment_scam, s13) :- guaranteed_returns, channel(social_media).
scam(wallet_fraud, s14) :- wrong_transfer_claim, asks_wallet_transfer.
scam(wallet_fraud, s15) :- claims_telecom, asks_pin.
scam(remote_access_scam, s16) :- device_takeover, authority_impersonation.
scam(malicious_app, s17) :- asks_install_app, unsafe_link.
scam(courier_scam, s18) :- claims_courier, asks_advance_fee.
scam(courier_scam, s19) :- claims_courier, unsafe_link.
scam(family_emergency, s20) :- emotional_request, money_demand, unknown_sender.
scam(romance_scam, s21) :- romance_contact, money_demand.
scam(marketplace_scam, s22) :- marketplace_deal, asks_otp.
scam(marketplace_scam, s23) :- marketplace_deal, unsafe_link.
scam(otp_theft, s24) :- asks_otp, pressure_tactic.
scam(otp_theft, s25) :- asks_otp, unofficial_contact.
scam(bank_impersonation, s26) :- claims_bank, asks_pin.
scam(bank_impersonation, s27) :- claims_bank, asks_card_details.
scam(bank_impersonation, s28) :- claims_bank, personal_number_used, sensitive_info_request.
scam(phishing_link, s29) :- suspicious_link, asks_otp.
scam(phishing_link, s30) :- shortened_link, authority_impersonation.
scam(phishing_link, s31) :- fake_domain, asks_pin.
scam(lottery_prize, s32) :- prize_lottery, asks_advance_fee.
scam(lottery_prize, s33) :- prize_lottery, asks_cnic, unknown_sender.
scam(govt_aid_scam, s34) :- claims_government, asks_advance_fee.
scam(govt_aid_scam, s35) :- claims_government, suspicious_link, asks_cnic.
scam(fake_officer_threat, s36) :- claims_government, urgent_threat, asks_advance_fee.
scam(fake_officer_threat, s37) :- claims_government, asks_secrecy, money_demand.
scam(job_scam, s38) :- too_good_salary, asks_wallet_transfer.
scam(job_scam, s39) :- too_good_salary, personal_number_used, asks_advance_fee.
scam(job_scam, s40) :- too_good_salary, suspicious_link, unknown_sender.
scam(investment_scam, s41) :- guaranteed_returns, asks_wallet_transfer.
scam(investment_scam, s42) :- guaranteed_returns, asks_advance_fee.
scam(investment_scam, s43) :- guaranteed_returns, asks_secrecy.
scam(wallet_fraud, s44) :- claims_telecom, asks_otp.
scam(wallet_fraud, s45) :- wrong_transfer_claim, asks_otp.
scam(wallet_fraud, s46) :- asks_wallet_transfer, urgent_threat, unknown_sender.
scam(remote_access_scam, s47) :- asks_remote_access, claims_bank.
scam(remote_access_scam, s48) :- asks_install_app, asks_remote_access.
scam(malicious_app, s49) :- asks_install_app, unknown_sender.
scam(malicious_app, s50) :- asks_install_app, personal_number_used.
scam(courier_scam, s51) :- claims_courier, suspicious_link, asks_cnic.
scam(courier_scam, s52) :- claims_courier, urgent_threat, asks_advance_fee.
scam(family_emergency, s53) :- emotional_request, asks_wallet_transfer.
scam(family_emergency, s54) :- emotional_request, urgent_threat, asks_secrecy.
scam(romance_scam, s55) :- romance_contact, asks_wallet_transfer.
scam(romance_scam, s56) :- romance_contact, asks_advance_fee.
scam(marketplace_scam, s57) :- marketplace_deal, asks_pin.
scam(marketplace_scam, s58) :- marketplace_deal, asks_card_details.
scam(otp_theft, s59) :- asks_otp, personal_number_used.
scam(otp_theft, s60) :- asks_otp, asks_secrecy, unknown_sender.
scam(credit_card_activation_fraud, s61) :- card_activation_request, asks_advance_fee, asks_otp.
scam(credit_card_activation_fraud, s62) :- card_activation_request, asks_card_details, asks_advance_fee.
scam(otp_theft, s63) :- asks_otp, asks_card_details, asks_advance_fee.


%  Layer 3: DECISION RULES

% total risk score = sum of weights of every reported red flag
risk_score(S) :-
    findall(W, (weight(F, W), call(F)), Ws),
    sum_list(Ws, S).

% risk level (first matching rule wins, hence the cuts)
risk_level(critical) :- risk_score(S), S >= 12, !.
risk_level(high)     :- risk_score(S), S >= 7, !.
risk_level(medium)   :- risk_score(S), S >= 3, !.
risk_level(low).

% derived signals that are currently true (for the "why" panel)
derived(F) :-
    member(F, [sensitive_info_request, pressure_tactic, unsafe_link,
               authority_impersonation, money_demand, device_takeover,
               unofficial_contact, reward_bait, sloppy_message, credit_card_activation_attempt]),
    \+ \+ call(F).

% ---------- Advice rules (11 rules) ----------
action("Never share OTP, PIN, card details or CNIC photo. Banks and telecoms never ask for these.") :-
    sensitive_info_request.
action("Do not tap the link. Open the official app or type the official website yourself.") :-
    unsafe_link.
action("Hang up and call the official helpline printed on your card or the official website.") :-
    authority_impersonation, channel(call).
action("Verify the sender via the official app, website or branch before replying.") :-
    authority_impersonation, \+ channel(call).
action("Do not install any app or allow screen sharing/remote access (AnyDesk, TeamViewer etc.).") :-
    device_takeover.
action("Do not send money until you verify the person through a separate trusted channel. For a 'mistaken' transfer, ask your bank/wallet support to handle it.") :-
    money_demand.
action("Pause. Scammers create urgency and secrecy. Talk to a family member before acting.") :-
    pressure_tactic.
action("Block the number/account and report it on the platform.") :-
    unofficial_contact.
action("Too-good-to-be-true offers are the classic sign of fraud. Real jobs, prizes and investments never charge you first.") :-
    reward_bait.
action("Report to FIA Cyber Crime Wing (helpline 1991) and inform your bank immediately if you already shared data or money.") :-
    risk_level(L), memberchk(L, [high, critical]).
action("No strong red flags found, but stay alert and never share your OTP.") :-
    risk_level(L), L == low.

%  Entry point: prints machine-readable lines for Python

run :-
    risk_score(S), risk_level(L),
    format("SCORE|~w~n", [S]),
    format("LEVEL|~w~n", [L]),
    forall(derived(D), format("FLAG|~w~n", [D])),
    findall(T-R, scam(T, R), Raw), sort(Raw, Found),
    forall(member(T1-R1, Found),
           ( describe(T1, Txt), format("SCAM|~w|~w|~w~n", [T1, R1, Txt]) )),
    findall(A, action(A), As0), list_to_set(As0, As),
    forall(member(A1, As), format("ACTION|~w~n", [A1])).
