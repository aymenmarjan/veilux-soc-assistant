importScripts('connector_parameters.js');
self.onmessage = event => {
  self.postMessage({started:true});
  try { self.postMessage({result:ConnectorParameters.resolve(event.data.rules,event.data.inputs)}); }
  catch(error) { self.postMessage({error:error.message}); }
};
