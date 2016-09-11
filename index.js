/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request'),
  n = require('nonce')(),
  oauthSignature = require("oauth-signature"),
  qs = require("qs");

var yelpConsumerKey = process.env.YELP_CONSUMER_KEY;
var yelpConsumerSecret = process.env.YELP_CONSUMER_SECRET;
var yelpToken = process.env.YELP_TOKEN;
var yelpTokenSecret = process.env.YELP_TOKEN_SECRET;

// var preferred_cuisine = "";
// var location_lat = "";
// var location_long = "";

var global_context = {};

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query['account_linking_token'];
  var redirectURI = req.query['redirect_uri'];

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;

      case 'read receipt':
        sendReadReceipt(senderID);
        break;

      case 'typing on':
        sendTypingOn(senderID);
        break;

      case 'typing off':
        sendTypingOff(senderID);
        break;

      case 'account linking':
        sendAccountLinking(senderID);
        break;

      case 'preferred cuisine':
        sendPreferredCuisineMessage(senderID);
        break;

      case 'hi':
        sendHiMessage(senderID);
        break;

      case 'Hi':
        sendHiMessage(senderID);
        break;

      default:
        // sendTextMessage(senderID, messageText);
        sendRestaurantMessage(senderID, messageText);
    }
  } else if (messageAttachments) {
    if (messageAttachments[0].payload != null && messageAttachments[0].payload.hasOwnProperty('coordinates')) {
      sendLocationMessage(senderID, messageAttachments);
    } else {
      sendTextMessage(senderID, "Message with attachment received");
    }
  }
}


function sendHiMessage (recipientId) {
  var userName = getUserName(recipientId);
  var output_text = "Hi " + userName + " ! What would you like me to pick you today? (ex: \"Pick me a mexican restaurant\").";
   
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: output_text,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to
  // let them know it was successful
  sendHiMessage(senderID);
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

function checkUserInGlobalContext(recipientId) {
  if (!(recipientId in global_context)) {
    global_context[recipientId] = {
      preferred_cuisine: "",
      location_lat: "",
      location_long: ""
    };
  }
}

/*
 * Send a Restaurant message using the Send API.
 *
 */
function getCuisineType(recipientId, messageText) {

  var cuisine_list = ["mexican", 'italian', 'chinese', 'korean',
  'japanese', 'american', 'french', 'german', 'sushi', 'indian', 'thai',
  'russian', 'south african'];
  var cuisine_type = false;
  var normalized_messageText = messageText.toLowerCase();

  for (var i = 0; i < cuisine_list.length; i++) {
    var cuisine = cuisine_list[i]
    if (normalized_messageText.indexOf(cuisine) !== -1) {
      cuisine_type = cuisine;
      checkUserInGlobalContext(recipientId)
      global_context[recipientId]['preferred_cuisine'] = cuisine;
      // preferred_cuisine = cuisine;
    }
  }

  return cuisine_type;
}

function sendPreferredCuisineMessage(recipientId) {

  var output_text = "No preferred cuisine specified";

  checkUserInGlobalContext(recipientId)
  var preferred_cuisine = global_context[recipientId]['preferred_cuisine']
  if (preferred_cuisine != "") {
    output_text = "Preferred cuisine is " + preferred_cuisine;
  }

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: output_text,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Restaurant message using the Send API.
 *
 */
function sendRestaurantMessage(recipientId, messageText) {
  checkUserInGlobalContext(recipientId)

  // Get cuisine.
  // Replace this with watson to get intent and entity.
  var cuisine = getCuisineType(recipientId, messageText);

  var have_cuisine = (global_context[recipientId]['preferred_cuisine'] != "");
  var have_location = (global_context[recipientId]['location_lat'] != "");

  var restaurantMessageText = "";

  if (have_cuisine && have_location) {
	  sendMessageToUserFromYelpResult(recipientId);
  } else {
	if (have_location) {
      restaurantMessageText = "What type of food would you like to eat? (eg. Mexican food).";
    } else {
      restaurantMessageText = "Where are you? (use the location button)";
    }
	var messageData = {
      recipient: {
        id: recipientId
      },
      message: {
        text: restaurantMessageText,
        metadata: "DEVELOPER_DEFINED_METADATA"
      }
    };
	callSendAPI(messageData);
  }
}

function sendMessageToUserFromYelpResult(recipientId) {
  checkUserInGlobalContext(recipientId)

  var preferred_cuisine = global_context[recipientId]['preferred_cuisine'];
  var location_lat = global_context[recipientId]['location_lat'];
  var location_long = global_context[recipientId]['location_long'];
	yelpMakeQuery("meat", preferred_cuisine, {lat: location_lat, long: location_long}, 10000, function(result) {
		var messageData = {
		  recipient: {
			id: recipientId
		  },
		  message: {
			text: "I highly recommend this place. It has great " + preferred_cuisine + " food.",
			metadata: "DEVELOPER_DEFINED_METADATA"
		  }
		};
	   callSendAPI(messageData);

  //   // result. : name, image, phone, street, city, 
  //   // crossroad (may be empty), latitude, longitude, is_closed (true/false)
  //   console.log('image');
  //   console.log(result.image);
  //   var large_image = result.image.replace('ms.jpg', 'ls.jpg')
  //   console.log(large_image);
  //   var imageMessageData = {
  //     recipient: {
  //       id: recipientId
  //     },
  //     message: {
  //       attachment: {
  //         type: "image",
  //         payload: {
  //           url: large_image
  //         }
  //       }
  //     }
  //   };
  //   callSendAPI(imageMessageData);

    // http://stackoverflow.com/questions/38017382/how-to-send-location-from-facebook-messenger-platform
    var mapMessageData = {
      recipient: {
        id: recipientId
      },
      message: {
          attachment: {
              type: "template",
              payload: {
                  template_type: "generic",
                  elements: {
                      element: {
                          title: result.name,
                          image_url: "https:\/\/maps.googleapis.com\/maps\/api\/staticmap?size=764x400&center="+result.latitude+","+result.longitude+"&zoom=25&markers="+result.latitude+","+result.longitude,
                          item_url: "http:\/\/maps.apple.com\/maps?q="+result.latitude+","+result.longitude+"&z=16"
                      }
                  }
              }
          }
      }
    };
    callSendAPI(mapMessageData);
  });
}

/*
 * Send get the GPS location and send a confirmation via the Send API.
 *
 */
function sendLocationMessage(senderID, messageAttachments) {
  checkUserInGlobalContext(senderID);

  var location_lat = messageAttachments[0].payload.coordinates.lat;
  var location_long = messageAttachments[0].payload.coordinates.long;
  global_context[senderID]['location_lat']  = location_lat;
  global_context[senderID]['location_long'] = location_long;

  var preferred_cuisine = global_context[senderID]['preferred_cuisine'];
  if (preferred_cuisine != "") {
	  sendMessageToUserFromYelpResult(senderID);
	  return;
  }

  console.log("location lat and long:");
  console.log(location_lat);
  console.log(location_long);

  var locationMessageText = "What kind of food would you like?";

  var messageData = {
    recipient: {
      id: senderID
    },
    message: {
      text: locationMessageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPED_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",
          timestamp: "1428444852",
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      console.error(response.error);
    }
  });
}

function getUserName(recipientId) {
  request('https://graph.facebook.com/v2.6/' + recipientId + '?access_token=' + PAGE_ACCESS_TOKEN, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      return (body.first_name);
    }
    else {
      console.log(error);
    }
  })
}




var yelpMakeQuery = function(term, type, location, radius, callback) {
	var httpMethod = 'GET';
    var url = 'https://api.yelp.com/v2/search/';
    var parameters = {
        oauth_consumer_key: yelpConsumerKey,
		oauth_nonce: n(),
		oauth_signature_method: 'HMAC-SHA1',
		oauth_timestamp: n().toString().substr(0,10),
        oauth_token: yelpToken,
		term: term,
		limit: 12,
		radius_filter: radius,
		category_filter: type
    };
	if (typeof location == "string") {
		parameters.location = location;
	} else if (typeof location == "object") {
		if (location.hasOwnProperty("lat") && location.hasOwnProperty("long")) {
			parameters.ll = parseFloat(location.lat) + "," + parseFloat(location.long);
		}
	}
    var consumerSecret = yelpConsumerSecret;
    var tokenSecret = yelpTokenSecret;
    var signature = oauthSignature.generate(httpMethod, url, parameters, consumerSecret, tokenSecret, { encodeSignature: false});
	parameters.oauth_signature = signature;
	var paramUrl = qs.stringify(parameters);
	var queryUrl = url + "?" + paramUrl;

	request(queryUrl, function(error, response, body) {
		if (!error && response.statusCode == 200) {
			yelpParseResponseBody(JSON.parse(body), function(result) {
				callback(yelpReturnFormattedResult(result));
			});
		} else {
			console.log("Error getting response from Yelp");
		}
	});
};

var yelpParseResponseBody = function(body, callback) {
	var total = 0;
	var result;

	if (body.hasOwnProperty("businesses")) {
		total = body.businesses.length;
		result = body.businesses[0];
		body.businesses.forEach(function(business) {
			total -= 1;
			if (business.hasOwnProperty("rating") && business.hasOwnProperty("review_count")) {
				if (business.rating > result.rating && business.review_count > 20) {
					result = business;
				}
			}
			if (total <= 0) {
				callback(result);
			}
		});
	}
};

var yelpReturnFormattedResult = function(result) {
	var res = {
		name: result.name,
		rating: result.rating,
	};
	if (result.hasOwnProperty('phone')) { res.phone = result.phone; }
	if (result.hasOwnProperty('image_url')) { res.image = result.image_url; }
	if (result.hasOwnProperty('location')) {
		res.street = result.location.address[0];
		res.city = result.location.city;
		if (result.location.hasOwnProperty("cross_streets")) {
			res.crossroad = result.location.cross_streets;
		}
		if (result.location.hasOwnProperty("coordinate")) {
			res.latitude = result.location.coordinate.latitude;
			res.longitude = result.location.coordinate.longitude;
		}
	}
	if (result.hasOwnProperty('is_closed')) { res.is_closed = result.is_closed; }
	return (res);
};




// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
