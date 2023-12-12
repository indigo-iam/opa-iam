async function authorize_operation(r) {
  
  try {

    const opa_input = { "id": r.variables["id"], "scopes": r.variables["scopes"] };
  
    const opts = {
      method: "POST",
      body: JSON.stringify(opa_input)
    };
  
    r.subrequest("/_opa", opts, function (opa_res) {
      r.log(`OPA Responded with status ${opa_res.status}`);
      r.log(JSON.stringify(opa_res));
  
      const body = JSON.parse(opa_res.responseText);
  
      if (!body || !body.allow) {
        r.return(403);
        return;
      }
  
      r.return(200);
    });
  
  } catch (err) {
    r.log(`Exception: ${err}`);
    r.return(403);
  }
  
  }
  
  export default { authorize_operation }
  