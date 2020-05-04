Fabric CA Deployment Guide
============================

This guide will illustrate how to setup a Fabric CA for a production network using the Fabric CA binaries.  After you have mastered deploying and running a CA by using these binaries, it is likely you will want to use the Fabric CA image instead, for example in a Kubernetes or Docker deployment. For now though, the purpose of this guide is to teach you how to properly use the binaries. Then the process can be extended to other environments.

The first topic introduces you to planning for a CA and deciding on the CA topology that is required for your organization.  Next, you should review the checklist for a production CA server to understand the most common configuration parameters for a CA and how they interact with each other. Finally, the CA deployment steps walk you through the process of configuring a TLS CA, an organization CA, and optionally, an intermediate CA for your production network. When this configuration is complete, you are ready to use the organization CA, or intermediate CA if you create one, to register and enroll the identities for your organization.

.. toctree::
   :maxdepth: 1
   :caption: Deploying a Production CA

   ca-deploy-topology
   ca-config
   cadeploy
   use_CA
