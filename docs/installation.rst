Installation
===============

Run with Docker
----------------

Get Docker
^^^^^^^^^^

SupplyShield can be installed using Docker Compose. The following steps will guide you through the installation process:

Install Docker
^^^^^^^^^^^^^^

First, you need to have Docker installed on your machine. If you haven't installed Docker yet, you can download it from the official Docker website at https://www.docker.com/get-started and follow the instructions for your operating system.

Get the Source Code
^^^^^^^^^^^^^^^^^^^

Clone the repository and navigate to the project directory:

   .. code-block:: bash

      git clone 
      cd supplyshield

Configure the Environment Variables
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Copy `docker.env.sample` to `docker.env` and update the environment variables to match your configuration. The configuration file contains few mandatory variables that need to be set before starting the application.

   .. code-block:: bash
         
         cp docker.env.sample docker.env
   
Run the docker
^^^^^^^^^^^^^^

Run the following command to start the application:

   .. code-block:: bash

      docker compose up

This will start the SupplyShield application and required services. SupplyShield will now start listening to the configured SQS queue for messages and process them. 

Send a message to the SQS queue
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sending a message to the SQS queue will trigger the SupplyShield pipeline to start processing the message. The pipeline will generate an SBOM, scan the dependencies, and identify vulnerabilities. 
Format of the message is as described in the wasp section.

At this point, SupplyShield would have started and would be listening for scan requests. 

.. note::
    This will start:
        1. A PostgreSQL database
        2. SupplyShield API service
        3. SupplyShield Daemon service
        4. SupplyShield Cron service
        5. An empty Metabase instance

Interface
----------

SupplyShield currently provides an interface using metabase.