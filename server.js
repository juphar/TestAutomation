
/**
 * Module dependencies.
 */

 //Prototypes
 String.prototype.includes = function(search, start) {
  if (typeof start !== 'number') {
    start = 0;
  }

  if (start + search.length > this.length) {
    return false;
  } else {
    return this.indexOf(search, start) !== -1;
  }
};

var express = require('express'),
  routes = require('./routes'),
  //Probably do not need any socketing, but here incase
  socket = require('./routes/socket.js'),
  cookieParser = require('cookie-parser'),
  http = require('http'),
  engines = require('consolidate'),
  bodyParser  = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;

var app = module.exports.app = express();
var server = http.createServer(app);

// Hook Socket.io into Express
var io = require('socket.io').listen(server);

//Set up port
var port = process.env.PORT || 3000;



// Configuration
app.set('views', __dirname + '/views');
app.engine('html', engines.mustache);
app.set('view engine', 'html');
app.set('view options', {
  layout: false
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded())
app.use(express.static(__dirname + '/public'));
app.use(session({resave: 'true', saveUninitialized: 'true' , secret: 'keyboard cat'}));
app.use(passport.initialize());
app.use(passport.session());
//Redirect all non HTTPS traffic to HTTPS (unless on localhost)
app.use(function(req, res, next) {
  if(req.get('Host').includes('localhost'))
    return next();
  else if(req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(['https://', req.get('Host'), req.url].join(''));
  }
  return next();
});


passport.serializeUser(function(user, done) {
 done(null, user);
});

passport.deserializeUser(function(obj, done) {
 done(null, obj);
});
var services = JSON.parse(process.env.VCAP_SERVICES || "{}");
if(services.SingleSignOn !== undefined) {
  var ssoConfig = services.SingleSignOn[0];
  var client_id = ssoConfig.credentials.clientId;
  var client_secret = ssoConfig.credentials.secret;
  var authorization_url = ssoConfig.credentials.authorizationEndpointUrl;
  var token_url = ssoConfig.credentials.tokenEndpointUrl;
  var issuer_id = ssoConfig.credentials.issuerIdentifier;
  const callback_url = 'https://' + JSON.parse(process.env.VCAP_APPLICATION).application_uris[0] + '/auth/sso/callback';

  //auth
  var Strategy = new OpenIDConnectStrategy({
                   authorizationURL : authorization_url,
                   tokenURL : token_url,
                   clientID : client_id,
                   scope: 'openid',
                   response_type: 'code',
                   clientSecret : client_secret,
                   callbackURL : callback_url,
                   skipUserProfile: true,
                   issuer: issuer_id},
  	function (iss, sub, profile, accessToken, refreshToken, params, done){
  	         	process.nextTick(function (){
  		profile.accessToken = accessToken;
  		profile.refreshToken = refreshToken;
  		done(null, profile);
           	})
  });

  passport.use(Strategy);
};
app.get('/login', passport.authenticate('openidconnect', {}));

function ensureAuthenticated(req, res, next) {
   console.log('starting auth');
   //If there is no SSO, then skip auth
   if(services.SingleSignOn !== undefined){
    if(!req.isAuthenticated()) {
          if(req.originalUrl === '/favicon.ico')
            req.session.originalUrl = '/';
          else
            req.session.originalUrl = req.originalUrl;
          console.error('reroute to log in');
          res.redirect('/login');
    } else {
      console.log('already authd, load page');
      return next();
    }
  }
  else {
    return next();
  }
}

app.get('/auth/sso/callback',function(req,res,next) {
  console.error('callback reached, heading to home route');
  var redirect_url = req.session.originalUrl;
  if(req.session.originalUrl === undefined || req.session.originalUrl === '')
    redirect_url = '/';

  passport.authenticate('openidconnect',{
           successRedirect: redirect_url,
           failureRedirect: '/failure',
  })(req,res,next);
});

app.get('/logout', (req, res, next) => {
  req.logout()
  res.redirect('https://' + issuer_id + '/idaas/mtfim/sps/idaas/logout');
})


// Routes
//ensureAuthenticated is a service to authenticate all users via SSO.
app.get('/', ensureAuthenticated, routes.index);
app.get('/partials/:name', ensureAuthenticated, routes.partials);
app.get('/wireframe', ensureAuthenticated, routes.wireframe);
app.get('/popup', ensureAuthenticated, routes.popup);
app.get('/testing', ensureAuthenticated, routes.testing);
app.get('/home', ensureAuthenticated, routes.home);
app.get('/history', ensureAuthenticated, routes.history);

// File for routes
require('./routes/routes')(app);
require('./routes/testing')(app);
//require('./routes/myApp')(app);

// Socket.io Communication
io.sockets.on('connection', socket);

// Start server

server.listen(port, function(){
  console.log("Express server listening on " + port);
});
