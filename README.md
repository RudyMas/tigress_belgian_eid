# tigress_belgian_eid
Tigress Module to process signing of PDF-documents with a Belgian eID

## Installation (for the Production Environment)

1. Install the dependencies:

   ```bash
   composer install tigress/belgian-eid
   ```
This will install the module and its dependencies inside your project
  
  

## Installation (for the Development Environment)

1. Install the dependencies:

   ```bash
   npm install
   ```

2. Run the Web-eID setup script to copy the required Web-eID library assets:

   ```bash
   npm run web-eid-setup
   ```

## Configuration

1. Register the module's routes. Add the following entry to your `config/routes.json` file in your project:

   ```json
   "extraRoutes": [
     {
       "package": "tigress/belgian-eid"
     }
   ]
   ```

   If `extraRoutes` already exists in your config, simply add the object to the existing array.

