## Setup Instruction

To run, switch to directory:

```
cd LiveNX/integrations/ips-ports/
```

create `.env` file from `.env.sample` and add your values

run the script by exporting .env variables

```
export $(grep -v '^#' .env | xargs) && python ips-ports.py 
```