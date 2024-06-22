package com.test.poc;

import com.google.gson.JsonObject;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class SamlController {

    @Autowired
    private SamlExecutor samlExecutor;

    @RequestMapping(method = RequestMethod.POST, value = "saml/authenticate",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonObject> samlAuthenticateAPI(@RequestBody JsonObject request) {
        JsonObject result = samlExecutor.processApiRequest(request);

        ResponseEntity<JsonObject> response = new ResponseEntity<>(result, HttpStatus.OK);

        return response;
    }

    @RequestMapping(method = RequestMethod.POST, value = "saml/consumer",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<JsonObject> samlAuthenticateAPI(@RequestBody String request) {
        System.out.println("============SAMLResponse===========");
        System.out.println(request);

        JsonObject result = new JsonObject();
        result.addProperty("status", "success");

        ResponseEntity<JsonObject> response = new ResponseEntity<>(result, HttpStatus.OK);

        return response;
    }
}
