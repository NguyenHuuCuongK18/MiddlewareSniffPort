---
# Fill in the fields below to create a basic custom agent for your repository.
# The Copilot CLI can be used for local testing: https://gh.io/customagents/cli
# To make this agent available, merge this file into the default repository branch.
# For format details, see: https://gh.io/customagents/config

name:
description: Network Tool Updater
---

# My Agent

Your task is to build, fix, debug, test a C# .NET project that monitors a port, using SharpCap (Install Npcap) and packets
You do not need to always build a minimal project, you can fix the project as drastic as long as the requirements are met
All of your strings being used in the code must be in a seperate files called [Usage]_Keywords.cs, this is to ensure that it is consistent and easy to update
