# PRESENTATION SCRIPT
**Digital Infrastructure as a War Target — The Rise of Cyberwarfare**
JKUAT · ICT Seminar 2025 · Your Name

> **Before you start:** Flask is running. ngrok is live. Dashboard is open in a tab. Portal link is ready to share. You have two browser windows — one showing the dashboard, one ready for the portal demo.

---

## SLIDE 1 — Title

*[Stand. Pause. Let the slide breathe for 3 seconds before speaking.]*

"Good morning everyone.

My name is [Your Name], and what I'm going to show you today is not a simulation of something that might happen.

It is a simulation of something that *is* happening — to universities, to students, and based on the data I'm going to show you, to institutions right here in Kenya.

My objective is to demonstrate the vulnerability of institutional digital infrastructure by simulating a live phishing attack on a university student portal — specifically, a replica of *this* university's portal — and show you exactly what an attacker sees when one of us clicks the wrong link."

*[Click to next slide.]*

---

## SLIDE 2 — The Scale

*[Point to each number as you say it.]*

"Let me give you three numbers before we get into the case studies.

Two thousand three hundred. That is the number of cyberattacks targeting universities — globally — every single week. Not per year. Per week. That figure comes from EDUCAUSE's 2024 annual report, and they have named education the number one targeted sector by hackers on the planet.

Thirty-two percent. That is how much phishing in Kenya increased in a single quarter — Q3 of 2023 — according to Kaspersky. Not globally. Here. In this country.

Eighty-three million dollars. That is what Kenya lost to cybercrime in 2023 alone, confirmed by the Communications Authority of Kenya.

This is not a first-world problem. This is not a theoretical risk. The numbers are local, they are recent, and they are growing."

*[Click.]*

---

## SLIDE 3 — Case Study 01: Lincoln College

*[Slow down here. Let the headline land.]*

"In December 2021, a college in Illinois — Lincoln College — was hit by ransomware delivered by Iranian hackers.

The attack encrypted everything. Recruitment systems. Student retention. Fundraising. All of it. Inoperable for three months.

They paid the ransom. They got access back.

And when they looked at the projections — how many students would enroll — the numbers were fatal. They could not recover.

On May 13, 2022, Lincoln College closed permanently. Six hundred students. One hundred and fifty-seven years of history. Gone.

This college survived two World Wars, the Great Depression, the 1918 flu, the 2008 financial crisis — and it could not survive one cyberattack.

*[Pause.]*

The entry point? A single phishing vector. No multi-factor authentication. No network segmentation. One click."

*[Click.]*

---

## SLIDE 4 — Case Study 02: University of Pisa + Kenya

"The University of Pisa. June 2022.

The BlackCat ransomware group hit via compromised staff credentials — credentials most likely obtained through phishing.

The demand: four point five million dollars. The largest ransom ever demanded from an academic institution. Student records. Research data. Financial systems. All exposed.

Now — on the right side of this slide — Kenya.

A prominent Kenyan university was breached in 2022(KU). Student records, academic information, financial data — exfiltrated. The name of the institution was not published, but the breach was documented in peer-reviewed research published in the UNESCO Kenya journal.

*[Pause. Look at the room.]*

Same vulnerability. Same entry point. Different continent. Same result.

The threat is not somewhere else. It is here."

*[Click.]*

---

## SLIDE 5 — Case Study 03: MOVEit + Cornell

"May 2023. A group called Cl0p discovered a zero-day vulnerability in a piece of file transfer software called MOVEit. They exploited it simultaneously across hundreds of organisations worldwide.

Among them: Johns Hopkins University, University of Georgia, and multiple universities across the UK. Student and staff personal data was published publicly online. Not sold on the dark web — published. Anyone could see it.

Now here is what makes this relevant to what we built.

Cornell University analysed two thousand three hundred phishing emails sent to universities between 2010 and 2023. Their finding: phishing lures have completely shifted. They no longer look like spam. They look like a job offer, a scholarship alert, an exam result notification. And thanks to AI, they now contain near-zero spelling errors.

*[Look up from notes.]*

If you cannot tell a fake email from a real one — you cannot tell a fake portal from a real one either.

Which brings me to what we actually built."

*[Click.]*

---

## SLIDE 6 — What We Built

"So. We built the attack.

Four steps. All running on a laptop, deployed globally in under a minute.

Step one: Clone. We built a pixel-perfect replica of the JKUAT student portal. Same logo. Same green branding. Same split-screen layout. Same copyright footer at the bottom — Copyright 2026, ABNO Softwares International. If you did not know what you were looking for, you would not know it was fake.

Step two: Deliver. We used ngrok — a free tool — to give the fake portal a public HTTPS link. No malware. No server. Any device, any browser. We shared it exactly the way a real attacker would.

Step three: Harvest. When someone submits the form, our Flask backend captures the credentials in plaintext. Then a loading spinner appears — it looks like the portal is signing you in. In the background, silently, four things happen: IP geolocation, passive device fingerprinting, and a camera permission prompt disguised as a security verification check.

Step four: Expose. Everything lands on our attacker dashboard — live, in real time.

*[Pause.]*

Let me show you."

*[Click to the DEMO slide. Switch to browser.]*

---

## SLIDE 7 — DEMO SLIDE *(you are now in the browser)*

*[Keep the DEMO slide on the projector. Open your browser.]*

*[Share the ngrok portal link — write it on the board or display it briefly.]*

"This is the portal link. I want someone in this room to open it on their phone.

*[Wait for a volunteer or a classmate you briefed.]*

While they open it — here is what I want you to watch for. Three things. Their password in plaintext. Their location and ISP. And, if they allow the camera — their face.

*[Wait for the person to open the portal and log in.]*

*[Switch to the dashboard tab once they submit.]*

Look at this.

Password — in plaintext. Right there.

Location — Nairobi. On [ISP name].

*[If camera was allowed:]* And there — that is their face. Taken the moment they clicked Allow on what they thought was a security check.

This is what the attacker sees. Instantly. From one form submission. Zero malware. Zero installation. A free Python framework and an afternoon."

*[Switch back to the slides. Click to Slide 8.]*

---

## SLIDE 8 — What It Captured

*[Read through the six items calmly — don't rush.]*

"Let me be specific about what we captured from a single login attempt.

Credentials — registration number and password, in plaintext, ready to use immediately on any system where that password is reused.

Geolocation — city, region, country, and ISP from the IP address. No permission required. Instant.

Camera photograph — a front-facing selfie, captured via the browser's getUserMedia API, framed as a security verification step on the loading page.

Device fingerprint — screen resolution, operating system, CPU core count, RAM, timezone, and a canvas fingerprint hash — all collected passively. Zero permissions.

Browser profile — language, installed plugins, Do Not Track status — combined into a uniqueness score. On most devices, this score is above eighty-five percent. That means you are identifiable across the entire internet without cookies.

And student record — name, course, year of study, GPA — matched from the registration number.

*[Pause.]*

All of this from someone who typed their password into what looked like the JKUAT portal."

*[Click.]*

---

## SLIDE 9 — Conclusion

*[Slow, confident delivery.]*

"The threat is not hypothetical. It takes one click.

Lincoln College: one attack shut down a hundred and fifty-seven years of history.

University of Pisa: phished credentials led to a four-point-five-million-dollar ransom demand.

Kenya 2023: phishing attacks rose thirty-two percent. Educational institutions are directly in the crosshairs.

And our simulation: we replicated the full attack chain — credential capture, geolocation, camera access, device fingerprinting, live attacker dashboard — in one afternoon, using free tools.

Three things must change.

First, mandatory multi-factor authentication on every university portal. Colonial Pipeline, Lincoln College, the University of Pisa — all fell because of a single unprotected credential. MFA would have stopped all of them.

Second, phishing simulation training. Research from Proofpoint shows that users who experience a controlled simulation like ours are seventy percent less likely to fall for a real attack. You just experienced one. You will not forget it.

Third, the Kenya Data Protection Act 2019 is not optional. Institutions that fail to protect student personal data face real legal liability. This is not a technical issue. It is a legal one.

*[Final pause. Look at the room.]*

The question is no longer *if* your institution will be targeted.

It is whether you will be ready when it is.

Thank you."

*[Stand still. Don't click. Don't speak. Let it land.]*

---

## LIKELY QUESTIONS FROM THE LECTURER — AND HOW TO ANSWER THEM

**Q: Is this legal? Did you get consent?**
> "Yes. This was a controlled educational simulation. All participants were volunteers who understood they were part of a demo. No real credentials were stored beyond the session — the data lives in memory only and disappears when Flask restarts. This mirrors how penetration testers and security researchers operate under a defined scope of engagement."

**Q: What stops a real attacker from doing exactly this?**
> "Nothing technical. That is the point. The barrier to entry is an afternoon and a free Python framework. The only defence is user awareness, MFA, and institutional policy — which is precisely what our conclusion argues for."

**Q: Why did you use JKUAT's actual branding?**
> "To demonstrate the realistic threat. A generic fake portal doesn't make the point. The argument is that *this* institution, with *these* students, is vulnerable right now. Using a generic design would have been dishonest about the severity."

**Q: What is the difference between what you did and an actual phishing attack?**
> "Three things: consent, scope, and intent. We briefed participants, we operated within a defined demo environment, and we did not use the data for harm. A real attacker has none of those constraints — which is exactly why the data we captured in a controlled setting should concern everyone in this room."

**Q: How would you defend against this?**
> "MFA as the first line — it makes a stolen password useless on its own. Second, phishing awareness training using exactly this kind of simulation. Third, institutional policy requiring that no login page should ever request camera access — users should be trained to flag that immediately as a red signal."

---

## TIMING GUIDE

| Slide | Time |
|---|---|
| 1 — Title | 1 min |
| 2 — Scale | 2 min |
| 3 — Lincoln College | 2.5 min |
| 4 — Pisa + Kenya | 2 min |
| 5 — MOVEit + Cornell | 2 min |
| 6 — What We Built | 2.5 min |
| 7 — LIVE DEMO | 4–6 min |
| 8 — What It Captured | 2 min |
| 9 — Conclusion | 2 min |
| **Total** | **~20 min** |

---

*Script prepared for JKUAT ICT Seminar 2025*
*Topic: Digital Infrastructure as a War Target — The Rise of Cyberwarfare*
