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

Manual Installation
------------------

This section describes how to install and run SupplyShield without Docker.

System Requirements
^^^^^^^^^^^^^^^^^

- Python 3.10 or higher
- Node.js (Latest LTS version)
- Java (Latest LTS version)
- PostgreSQL client
- Git

Install System Dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^

On Debian/Ubuntu systems, install the required system dependencies:

   .. code-block:: bash

      # Add NodeSource repository
      curl -fsSL https://deb.nodesource.com/setup_current.x | sudo bash -

      # Install system dependencies
      sudo apt-get update
      sudo apt-get install -y python3 \
          python3-pip \
          python3-dev \
          default-libmysqlclient-dev \
          build-essential \
          postgresql-client \
          libpq-dev \
          git \
          nodejs \
          jq \
          unzip \
          zip

      # Update npm to latest version
      sudo npm install npm@latest -g

Install Java using SDKMAN
^^^^^^^^^^^^^^^^^^^^^^^

Install Java using `SDKMAN <https://sdkman.io/>`_:

   .. code-block:: bash

      # Install SDKMAN
      curl -s "https://get.sdkman.io" | bash
      source "$HOME/.sdkman/bin/sdkman-init.sh"

      # Install Java versions and Maven
      sdk install java 19.0.2-zulu && \
      sdk install java 8.0.412-amzn && \
      sdk install java 11.0.23-amzn && \
      sdk install java 17.0.11-amzn && \
      sdk install java 21.0.2-amzn && \
      sdk install maven 3.9.8

Get the Source Code
^^^^^^^^^^^^^^^^^^^

Clone the repository and navigate to the project directory:

   .. code-block:: bash

      git clone 
      cd supplyshield

Create virtual environment
^^^^^^^^^^^^^^^^^^^^^^^^^^
Create a virtual environment using virtualenv and activate it

   .. code-block:: bash

      virtualenv venv
      source venv/bin/activate 

Install the application and build documentation:

   .. code-block:: bash

      make install
      make docs

Run libinv daemon
^^^^^^^^^^^^^^^^^

Start the application using make:

   .. code-block:: bash

      make run

Run libinv crons
^^^^^^^^^^^^^^^^

Start the application using make:

   .. code-block:: bash

      make crons

Run libinv web server
^^^^^^^^^^^^^^^^^^^^^

Start the application using make:

   .. code-block:: bash

      make startserver

The application will start and listen on port 8000 by default.

Interface
----------

SupplyShield currently provides an interface using metabase.
