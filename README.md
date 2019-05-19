### Authentication

Authentication is an **essential** part of most applications. There are a lot of different approaches and strategies to handle authentication. The approach taken for any project depends on its particular application requirements.  This chapter provides several approaches to authentication that can be adapted to a variety of different requirements.

[Passport](https://github.com/jaredhanson/passport) is the most popular node.js authentication library, well-known by the community and successfully used in many production applications. It's straightforward to integrate this library with a **Nest** application using the built-in `@nestjs/passport` module.

In this chapter, we'll consider two representative use cases, and implement a complete end-to-end authentication solution for each:
* Traditional web application with server-side template-driven HTML pages
* API server that accepts REST/HTTP requests and returns JSON responses

Note that in this chapter, we build the API Server use case on top of the Web application use case.  This is not required of course, but is useful for illustrating the core concepts of authentication.  At the end of the API Server section, we describe how to strip out the unnecessary components for an API server-only implementation.  Because of this, we recommend reading the entire chapter in the order presented, even if you're only interested in the API server use case.

#### Server-side web application use case

Let's flesh out our requirements. For this use case, users will authenticate with a username and password. Once authenticated, the server will utilize Express sessions so that the user remains "logged in" until they choose to log out.  We'll set up a protected route that is accessible only to an authenticated user.

 We start by installing the required packages, and building our basic routes.

 > Warning **Notice** For **any** Passport strategy you choose (there are many available [here](http://www.passportjs.org/packages/)), you'll always need the `@nestjs/passport` and `passport` packages. Then, you'll need to install the strategy-specific package (e.g., `passport-jwt` or `passport-local`) that scaffolds the particular authentication strategy you are building.

Passport provides a strategy called [passport-local](https://github.com/jaredhanson/passport-local) that implements a username/password authentication strategy, which suits our needs for this use case. Since we are rendering some basic HTML pages, we'll also install the versatile and popular [express-handlebars](https://github.com/ericf/express-handlebars) package to make that a little easier.  To support sessions and to provide a convenient way to give user feedback during login, we'll also utilize the express-session and connect-flash packages. With these basic requirements in mind, we can now start by scaffolding a brand new Nest application, and installing the dependencies:

```bash
$ nest new auth-sample
$ cd auth-sample
$ npm install --save @nestjs/passport passport passport-local express-handlebars express-session connect-flash @types/express
```
#### Web interface

Let's start by building the templates we'll use for the UI of our authentication subsystem.  Following a standard MVC type project structure, create the following folder structure (i.e., the `public` folder and its sub-folders):

<div class="file-tree">
  <div class="item">src</div>
  <div class="children">
    <div class="item">public</div>
    <div class="children">
      <div class="item">views</div>
      <div class="children">
        <div class="item">layouts</div>
      </div>
    </div>
  </div>
</div>

Now create the following handlebars templates, and configure Nest to use express-handlebars as the view engine.  Refer [here](https://handlebarsjs.com/) for more on the handlebars template language, and [here](https://docs.nestjs.com/techniques/mvc) for more background on Nest-specific techniques for Server side rendered (MVC style) web apps.

##### Main layout

Create `main.hbs` in the layouts folder, and add the following code.  This is the outermost container for our views.  Note the `{{ '{' }}{{ '{' }}{{ '{' }} body {{ '}' }}{{ '}' }}{{ '}' }}` line, which is where each individual view is inserted.  This structure allows us to set up global styles.  In this case, we're taking advantage of Google's widely used [material design lite](https://github.com/google/material-design-lite) component library to style our minimal UI. All of those dependencies are taken care of in the `<head>` section of our layout.

```html
<!-- src/public/views/layouts/main.hbs -->
<!DOCTYPE html>
<html>
  <head>
    <script src="https://code.getmdl.io/1.3.0/material.min.js"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.indigo-pink.min.css">
    <style>
      .mdl-layout__content {
        padding: 24px;
        flex: none;
      }
      .mdl-textfield__error {
        visibility: visible;
        padding: 5px;
      }
      .mdl-card {
        padding-bottom: 10px;
        min-width: 500px;
      }
    </style>
  </head>
  <body>
    {{ '{' }}{{ '{' }}{{ '{' }} body {{ '}' }}{{ '}' }}{{ '}' }}
  </body>
</html>
```

##### Home page

Create `home.hbs` in the `views` folder, and add the following code.  This is the page users land on after authenticating.
```html
<!-- src/public/views/home.hbs -->
<div class="mdl-layout mdl-js-layout mdl-color--grey-100">
  <main class="mdl-layout__content">
    <div class="mdl-card mdl-shadow--6dp">
      <div class="mdl-card__title mdl-color--primary mdl-color-text--white">
        <h2 class="mdl-card__title-text">Welcome {{ '{' }}{{ '{' }} user.username {{ '}' }}{{ '}' }}!</h2>
      </div>
      <div class="mdl-card__supporting-text">
        <div class="mdl-card__actions mdl-card--border">
          <a class="mdl-button" href='/profile'>GetProfile</a>
        </div>
      </div>
    </div>
  </main>
</div>
```
##### Login page

Create `login.hbs` in the `views` folder, and add the following code.  This is the login form.
```html
<!-- src/public/views/login.hbs -->
<div class="mdl-layout mdl-js-layout mdl-color--grey-100">
  <main class="mdl-layout__content">
    <div class="mdl-card mdl-shadow--6dp">
      <div class="mdl-card__title mdl-color--primary mdl-color-text--white">
        <h2 class="mdl-card__title-text">Nest Cats</h2>
      </div>
      <div class="mdl-card__supporting-text">
        <form action="/login" method="post">
          <div class="mdl-textfield mdl-js-textfield">
            <input class="mdl-textfield__input" type="text" name="username" id="username" />
            <label class="mdl-textfield__label" for="username">Username</label>
          </div>
          <div class="mdl-textfield mdl-js-textfield">
            <input class="mdl-textfield__input" type="password" name="password" id="password" />
            <label class="mdl-textfield__label" for="password">Password</label>
          </div>
          <div class="mdl-card__actions mdl-card--border">
            <button class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect">Log In</button>
            <span class="mdl-textfield__error">{{ '{' }}{{ '{' }} message {{ '}' }}{{ '}' }}</span>
          </div>
        </form>
      </div>
    </div>
  </main>
</div>
```
##### Profile page

Create `profile.hbs` in the `views` folder and add the following code.  This page displays details about the logged in user.  It's rendered on our protected route.
```html
<!-- src/public/views/profile.hbs -->
<div class="mdl-layout mdl-js-layout mdl-color--grey-100">
  <main class="mdl-layout__content">
    <div class="mdl-card mdl-shadow--6dp">
      <div class="mdl-card__title mdl-color--primary mdl-color-text--white">
        <h2 class="mdl-card__title-text">About {{ '{' }}{{ '{' }} user.username {{ '}' }}{{ '}' }}</h2>
      </div>
      <div>
        <figure><img src="http://lorempixel.com/400/200/cats/{{ '{' }}{{ '{' }}user.pet.picId{{ '}' }}{{ '}' }}">
          <figcaption>{{ '{' }}{{ '{' }} user.username {{ '}' }}{{ '}' }}'s friend {{ '{' }}{{ '{' }} user.petname {{ '}' }}{{ '}' }}</figcaption>
        </figure>
        <div class="mdl-card__actions mdl-card--border">
          <a class="mdl-button" href='/logout'>Log Out</a>
        </div>
      </div>
    </div>
  </main>
</div>
```

##### Set up view engine

Now we instruct Nest to use express-handlebars as the view engine.  Modify the `main.ts` file so that it looks like this:
```typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import { AppModule } from './app.module';
import * as exphbs from 'express-handlebars';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const viewsPath = join(__dirname, '/public/views');
  app.engine('.hbs', exphbs({ extname: '.hbs', defaultLayout: 'main' }));
  app.set('views', viewsPath);
  app.set('view engine', '.hbs');

  await app.listen(3000);
}
bootstrap();
```

##### Authentication routes
The final step in this section is setting up our routes.  Modify `app.controller.ts` so that it looks like this:
```typescript
// src/app.controller.ts
import { Controller, Get, Post, Request, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller()
export class AppController {
  @Get('/')
  index(@Request() req, @Res() res: Response) {
    res.render('login');
  }

  @Post('/login')
  login(@Request() req, @Res() res: Response) {
    res.redirect('/home');
  }

  @Get('/home')
  getHome(@Request() req, @Res() res: Response) {
    res.render('home');
  }

  @Get('/profile')
  getProfile(@Request() req, @Res() res: Response) {
    res.render('profile');
  }

  @Get('/logout')
  logout(@Request() req, @Res() res: Response) {
    res.redirect('/');
  }
}
```

At this point, you should be able to run the app:
```bash
$ npm run start
```
Now, browse to <a href="http://localhost:3000/">http://localhost:3000</a> and click through the basic UI.  At this point, of course, you can click through the pages without logging in.

#### Implementing Passport strategies

We're now ready to implement the authentication feature. Let's start with an overview of the process used for **any** Passport strategy.  It's helpful to think of Passport as a mini framework in itself. The elegance of the framework is that it abstracts the authentication process into a few basic steps that you customize based on the strategy you're implementing.  It's like a framework because you configure it by supplying custom code in the form of callback functions, which Passport calls at the appropriate time.  The nest-passport module wraps this framework in a Nest style package. We'll use that below, but first let's consider vanilla Passport.

In vanilla Passport, you configure a strategy by providing two things:
1. A set of options that are specific to that strategy.  For example, in a JWT strategy, you might provide a secret to sign tokens.
2. A "verify callback", which is where you tell Passport how to interact with your user store (where you manage user accounts). Here, you verify whether a user exists (or possibly create a new user), and whether their credentials are valid.

In Nest, you achieve these functions by extending the `PassportStrategy` class.  You pass the strategy options (item 1 above) by calling the `super()` method in your subclass, optionally passing in an options object.  You provide the verify callback (item 2 above) by implementing a `validate()` method in your subclass.

As mentioned, we'll utilize the passport-local strategy for this use case.  We'll get to that implementation in a moment.  Start by generating an `AuthModule` and in it, an `AuthService`:

```bash
$ nest g module auth
$ nest g service auth
```

As we implement the `AuthService`, we'll find it useful to have a `UsersService`, so let's generate that module and service now:

```bash
$ nest g module users
$ nest g service users
```

Replace the default contents of these generated files as shown below.  For our sample app, the `UsersService` simply maintains a hard-coded in-memory list of users, and a method to retrieve one by username.  In a real app, this is where you'd build your user model and persistence layer, using your library of choice (e.g., TypeORM, Sequelize, Mongoose, etc.).

```typescript
// src/users/users.service.ts
import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private readonly users;

  constructor() {
    this.users = [
      {
        userId: 1,
        username: 'john',
        password: 'changeme',
        pet: { name: 'alfred', picId: 1 },
      },
      {
        userId: 2,
        username: 'chris',
        password: 'secret',
        pet: { name: 'gopher', picId: 2 },
      },
      {
        userId: 3,
        username: 'maria',
        password: 'guess',
        pet: { name: 'jenny', picId: 3 },
      },
    ];
  }

  async findOne(username): Promise<any> {
    return this.users.filter(user => user.username === username)[0];
  }
}
```

In the `UsersModule`, the only change is to add the `UsersService` to the exports array of the `@Module` decorator so that it is visible outside this module (we'll soon use it in our `AuthService`).
```typescript
// src/users/users.module.ts
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';

@Module({
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
```

Our `AuthService` has the job of retrieving a user and verifying the password.

```typescript
// src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async validateUser(username, pass): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }
}
```

> Warning **Warning** Of course in a real application, you wouldn't store a password in plain text. You'd instead use a library like [bcrypt](https://github.com/kelektiv/node.bcrypt.js#readme), with a salted one-way hash algorithm. With that approach, you'd only store hashed passwords, and then compare the stored password to a hashed version of the **incoming** password, thus never storing or exposing user passwords in plain text. To keep our sample app simple, we violate that absolute mandate and use plain text.  **Don't do this in your real app!**

We'll call into our `validateUser()` method from our Passport local strategy subclass in a moment. The Passport library expects us to return a full user if the validation succeeds, or a null if it fails (failure is defined as either the user is not found, or the password does not match). In our code, we use a convenient ES6 spread operator to strip the password property from the user object before returning it. Upon successful validation, Passport then takes care of a few details for us, which we'll explore later on in the Sessions section.

And finally, we update our `AuthModule` to import the `UsersModule`.

```typescript
// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [UsersModule],
  providers: [AuthService],
})
export class AuthModule {}
```

Our app will function now, but remains incomplete until we finish a few more steps.  You can navigate to <a href="http://localhost:3000/">http://localhost:3000</a> and still move around without logging in (after all, we haven't implemented our Passport local strategy yet.  We'll get there momentarily).  Notice that if you **do** login (refer to the `UsersService` for username/passwords you can test with), the profile page now provides some (but not all) information about a "logged in" user.

#### Implementing Passport local

Now we can implement our Passport local **authentication strategy**.  Create a file called `local.strategy.ts` in the `auth` folder, and add the following code:

```typescript
// src/auth/local.strategy.ts
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super();
  }

  async validate(username: string, password: string) {
    const user = await this.authService.validateUser(username, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
```

We've followed the recipe described earlier for all Passport strategies.  In our use case with passport-local, there are no configuration options, so our constructor simply calls `super()`, without an options object.

We've also implemented the `validate()` method. For the local-strategy, Passport expects a `validate()` method with a signature like

```validate(username: string, password:string): any```

Most of the work is done in our `AuthService` (and in turn, in our `UserService`), so this method is quite straightforward. The `validate()` method for **any** Passport strategy will follow a similar pattern.  If a user is found and valid, it's returned so request handling can continue, and Passport can do some further housekeeping.  If it's not found, we throw an exception and let our <a href="exceptions">exceptions layer</a> handle it.

It turns out that the only really significant difference for each strategy is **how** you determine if a user exists and is "valid".  For example, in a JWT strategy, depending on requirements, we may evaluate whether the `userId` carried in the decoded token matches a record in our user database, or matches a list of revoked tokens.  Hence, this pattern of sub-classing and implementing strategy-specific validation is consistent, elegant and extensible.

With the strategy in place, we have a few more tasks to complete:
1. Create Guards we can use to decorate routes so that the configured Passport strategy is invoked
2. Add `@UseGuards()` decorators as needed
3. Implement sessions so that users can stay logged in across requests
4. Configure Nest to use Passport and session-related features
5. Add a little polish to the user experience

Let's get started.  For the following sections, we'll want to adhere to a best practice project structure, so start by creating a few more folders.  Under `src`, create a `common` folder.  Inside `common`, create `filters` and `guards` folders.  Our structure now looks like this:

<div class="file-tree">
  <div class="item">src</div>
  <div class="children">
    <div class="item">auth</div>
    <div class="item">common</div>
    <div class="children">
      <div class="item">filters</div>
      <div class="item">guards</div>
    </div>
    <div class="item">public</div>
    <div class="item">users</div>
  </div>
</div>

#### Implement guards

The <a href="guards">Guards</a> chapter describes the primary function of Guards: to determine whether a request will be handled by the route handler or not.  That remains true, and we'll use that feature soon.  However, in the context of using the nest-passport module, we will also introduce a slight new wrinkle that may at first be confusing, so let's discuss that now. Consider that your app can exist in two states, from an authentication perspective:
1. the user is **not** logged in (is not authenticated)
2. the user **is** logged in (is authenticated)

In the first case (user is not logged in), we need to perform two distinct functions.  First, we want to restrict the routes the unauthenticated user can access (i.e., deny access to restricted routes).  We'll use Guards in their familiar capacity to handle this function.  We'll do this through a standard, user-defined `AuthenticatedGuard` which we'll build shortly.

Next, we also need to handle the **authentication step** itself (i.e., when a previously unauthenticated user attempts to login) to kick things off: setting up our session, and transitioning from the unauthenticated state to the authenticated state.  Looking at our UI, it's easy to see that we'll handle this step via a `POST` request on our `/login` route. This raises the question: how exactly do we invoke the "login phase" of the Passport local strategy in that route?

The answer is: by using another Guard.  Similar to the way we extended the `PassportStrategy` class in the last section, we'll start with a default `AuthGuard` provided in the `@nestjs/passport` package, and extend it as needed, naming our new Guard `LoginGuard`.  We'll then decorate our `POST /login` route with this `LoginGuard` to invoke our Passport local strategy.

The second case enumerated above (logged in user) simply relies on the same standard user-defined `AuthenticatedGuard` we already discussed to enable access to protected routes for logged in users.

Let's cover the `LoginGuard` first. Create a file called `login.guard.ts` in the `guards` folder and replace its default contents as follows:

```typescript
// src/common/guards/login.guard.ts
import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LoginGuard extends AuthGuard('local') {
  async canActivate(context: ExecutionContext) {
    const result = (await super.canActivate(context)) as boolean;
    const request = context.switchToHttp().getRequest();
    await super.logIn(request);
    return result;
  }
}
```

There's a lot going on in these few lines of code, so let's walk through it.
* Our Passport local strategy has a default name of 'local'.  We reference that name in the `extends` clause of the `LoginGuard` we are defining in order to tie our custom Guard to the code supplied by the `passport-local` package. This is needed to disambiguate which class we are extending in case we end up using multiple Passport strategies in our app (each of which may provide a strategy-specific `AuthGuard`).
* As with all Guards, the primary method we define/override is `canActivate()`, which is what we do here.
* The body of `canActivate()` is setting up an Express session.  Here's what's happening:
    * we call `canActivate()` on the super class, as we normally would in extending a super class method. Our super class provides the framework for invoking our Passport local strategy.  Recall from the [Guards](https://docs.nestjs.com/guards) chapter that `canActivate()` returns a boolean indicating whether or not the target route will be called.  When we get here, Passport will have run the previously configured strategy (from the super class) and will return a boolean to indicate whether or not the user has successfully authenticated.  Here, we stash the result so we can do a little more processing before finally returning.
    * the key step for starting a session is to now invoke the `logIn()` method on our super class, passing in the current request.  This actually calls a special method that Passport automatically added to our Express `Request` object during the previous step.  See [here](http://www.passportjs.org/docs/configure/) and [here](http://www.passportjs.org/docs/login/) for more on Passport sessions and these special methods.
    * the Express session has now been setup, and we can return our `canActivate()` result, allowing only authenticated users to continue.

#### Sessions

Now that we've introduced sessions, there's one additional detail we need to take care of.  Sessions are a way of associating a unique user with some server-side state information about that user.

> warning **Notice** TBD: Add details on Passport sessions (deferred for this draft).  Seems important to provide context for how to implement the serialize/deserialize protocol.  Sadly, Passport docs don't have much here.

> warning **Notice** Also, I am not 100% comfortable explaining how **the following implementation** works.  I'll post a separate question about this.

Create the `session.serializer.ts` file in the `auth` folder, and add the following code:
```typescript
// src/auth/session.serializer.ts
import { PassportSerializer } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
@Injectable()
export class SessionSerializer extends PassportSerializer {
  serializeUser(user: any, done: Function): any {
    done(null, user);
  }
  deserializeUser(payload: any, done: Function): any {
    done(null, payload);
  }
}
```

We need to configure our `AuthModule` to use the Passport features we just defined. Update `auth.module.ts` to look like this:
```typescript
// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { SessionSerializer } from './session.serializer';

@Module({
  imports: [UsersModule, PassportModule],
  providers: [AuthService, LocalStrategy, SessionSerializer],
})
export class AuthModule {}
```

Now let's create our `AuthenticatedGuard`.  This is a traditional Guard, as covered in the <a href="https://docs.nestjs.com/guards">Guards</a> chapter. Its role is simply to protect certain routes. Create the file `authenticated.guard.ts` in the `guards` folder, and add the following code:

```typescript
// src/common/guards/authenticated.guard.ts
import { ExecutionContext, Injectable, CanActivate } from '@nestjs/common';

@Injectable()
export class AuthenticatedGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    return request.user;
  }
}
```

The only thing to point out here is that in order to determine whether a user is authenticated or not, we simply test for the presence of a `user` property on the `Request` object.  The reason this works is that Passport, upon successful authentication, automatically attaches this property to the `Request` object for us.

#### Configure Nest to bootstrap features

We can now instruct Nest to use the Passport features we've configured.  Update `main.ts` to look like this:

```typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import { AppModule } from './app.module';

import * as session from 'express-session';
import * as flash from 'connect-flash';
import * as exphbs from 'express-handlebars';
import * as passport from 'passport';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  const viewsPath = join(__dirname, '/public/views');
  app.engine('.hbs', exphbs({ extname: '.hbs', defaultLayout: 'main' }));
  app.set('views', viewsPath);
  app.set('view engine', '.hbs');

  app.use(
    session({
      secret: 'nest cats',
      resave: false,
      saveUninitialized: false,
    }),
  );

  app.use(passport.initialize());
  app.use(passport.session());
  app.use(flash());

  await app.listen(3000);
}
bootstrap();
```

Here, we've added the session and Passport support to our Nest app.

> Warning **Warning** As always, be sure to keep secrets out of your source code (**don't put your session secret in the code, as we did here; use environment variables or a config module instead**).

Note carefully that the order is important (register the session middleware first, then initialize Passport, then configure Passport to use sessions).  We'll see the use of the `flash` feature in a few minutes.

#### Add route guards

Now we're ready to start applying these Guards to routes.  Update `app.controller.ts` to look like this:

```typescript
// src/app.controller.ts
import { Controller, Get, Post, Request, Res, UseGuards } from '@nestjs/common';
import { Response } from 'express';

import { LoginGuard } from './common/guards/login.guard';
import { AuthenticatedGuard } from './common/guards/authenticated.guard';

@Controller()
export class AppController {
  @Get('/')
  index(@Request() req, @Res() res: Response) {
    res.render('login');
  }

  @UseGuards(LoginGuard)
  @Post('/login')
  login(@Request() req, @Res() res: Response) {
    res.redirect('/home');
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/home')
  getHome(@Request() req, @Res() res: Response) {
    res.render('home', { user: req.user });
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/profile')
  getProfile(@Request() req, @Res() res: Response) {
    res.render('profile', { user: req.user });
  }

  @Get('/logout')
  logout(@Request() req, @Res() res: Response) {
    req.logout();
    res.redirect('/');
  }
}
```

Above, we've imported our two new Guards and applied them appropriately.  We use the `LoginGuard` on our `POST /login` route to initiate the authentication sequence in the Passport local strategy.  We use `AuthenticatedGuard` on our protected routes to ensure they aren't accessible to unauthenticated users.

We're also taking advantage of the Passport feature that automatically stores our `User` object on the `Request` object as `req.user`.  With this handy feature, we can pass a variable into our handlebars templates (e.g., `res.render('profile', {{ '{' }} user: req.user {{ '}' }})`) to customize their content.

Finally, we have added the call to `req.logout()` in our `logout` route.  This relies on the Passport logout function, which, similar to the `logIn()` method we discussed earlier in the Sessions section, has been added to the Express `Request` object by Passport automatically upon successful authentication.  When we invoke `logout()`, Passport tears down our session for us.

You should now be able to test the authentication logic by attempting to navigate to a protected route.  Try pointing your browser at <a href="localhost:3000/profile">localhost:3000/profile</a>.  You should get a 403 Forbidden error.  Return to the root page at <a href="localhost:3000/">localhost:3000</a>, and log in.  Refer to `src/users/users.service.ts` for the hard-coded usernames and passwords that are accepted.

#### Adding polish
Let's address that ugly 403 Forbidden error page. If you navigate around the app, trying things like submitting an empty login request, a bad password, and logging out, you'll see that it's not a very good UX.  Let's take care of a couple of things:
1. Let's send the user back to the login page whenever they fail to authenticate, and when they log out of the app
2. Let's provide a little feedback when a user types in an incorrect password

The best way to handle the first requirement is to implement a <a href="exception-filters">Filter</a>.  Create the file `auth-exceptions.filter.ts` in the `filters` folder, and add the following code:

```typescript
// src/common/filters/auth-exceptions.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Response } from 'express';
import { Request } from 'connect-flash';

@Catch(HttpException)
export class AuthExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    if (
      exception instanceof UnauthorizedException ||
      exception instanceof ForbiddenException
    ) {
      request.flash('loginError', 'Please try again!');
      response.redirect('/');
    } else {
      response.redirect('/error');
    }
  }
}
```

The only new element here from what's covered in <a href="exception-filters">Filters</a> is the use of connect-flash.  If a route returns either an `UnauthorizedException` or a `ForbiddenException`, we redirect to the root route with `response.redirect('/')`.  We also use connect-flash to store a message in Passport's session.  This mechanism allows us to temporarily persist a message upon redirect.  Passport and connect-flash automatically take care of the details of storing, retrieving, and cleaning up those messages.

The final touch is to display the flash message in our handlebars template.  Update `app.controller.ts` to look like this.  In this update, we're adding the `AuthExceptionFilter` and adding the flash parameters to our index (`/`) route.

```typescript
// src/app.controller.tas
import { Controller, Get, Post, Request, Res, UseGuards, UseFilters } from '@nestjs/common';
import { Response } from 'express';
import { LoginGuard } from './common/guards/login.guard';
import { AuthenticatedGuard } from './common/guards/authenticated.guard';
import { AuthExceptionFilter } from './common/filters/auth-exceptions.filter';

@Controller()
@UseFilters(AuthExceptionFilter)
export class AppController {
  @Get('/')
  index(@Request() req, @Res() res: Response) {
    res.render('login', { message: req.flash('loginError') });
  }

  @UseGuards(LoginGuard)
  @Post('/login')
  login(@Request() req, @Res() res: Response) {
    res.redirect('/home');
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/home')
  getHome(@Request() req, @Res() res: Response) {
    res.render('home', { user: req.user });
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/profile')
  getProfile(@Request() req, @Res() res: Response) {
    res.render('profile', { user: req.user });
  }

  @Get('/logout')
  logout(@Request() req, @Res() res: Response) {
    req.logout();
    res.redirect('/');
  }
}
```

We now have a fully functional authentication system for our server side Web application.

#### API Server use case

Let's start by defining requirements. We're going to piggyback on the code written in the previous section.  This means our sample application will include both server-side rendered HTML pages and REST-based routes returning JSON responses. While this may not represent your particular requirements, you can customize the code as needed.  For example, in an API Server-only application, you can remove the session handling code, handlebars templates, and view engine components.  We take this approach for several reasons:
* Some applications do in fact serve both types of interaction
* Much of the code is common to both scenarios.  This demonstrates the abstraction power of both Nest and Passport, and shows how you can keep critical authentication code DRY

Specific to our API Server, we need to meet the following requirements:
* Allow users to authenticate, returning a [JSON Web Token(JWT)](https://jwt.io/) for use in subsequent calls to protected API endpoints
* Create API routes which are protected based on the presence of a valid JWT as a bearer token in an [Authorization header](https://tools.ietf.org/html/rfc6750)

We start by installing the packages required.  The only additions are the packages required to support a JWT authentication method:

```bash
$ npm install @nestjs/jwt passport-jwt
```

The `@nest/jwt` package (see more [here](https://github.com/nestjs/jwt)) is a utility package that helps with JWT manipulation.  The `passport-jwt` package is the Passport package that implements JWT authentication.

#### Define API module and routes

Now let's define a Module with a Controller to handle our API routes.  We'll call this our `ApiModule`, and we'll prefix all of its route paths with `/api`.

```bash
$ nest g module api
$ nest g controller api
```

Replace the default contents of the `api.controller.ts` file with the following:

```typescript
// src/api/api.controller.ts
import { Controller, Get, Request, Res, Post } from '@nestjs/common';
import { Response } from 'express';

@Controller('api')
export class ApiController {
  @Post('/login')
  async login(@Res() res: Response) {
    res.json({ access_token: 'sampletoken' });
  }

  @Get('/me')
  getProfile(@Res() res: Response) {
    res.json({
      userId: 1,
      username: 'john',
      pet: { name: 'alfred', picId: 1 },
    });
  }
}
```

We're going to stub both routes for now while we get our JWT infrastructure in place.

We stub the profile route (`GET /me`) because we don't know the identity of the user we should be returning.  Why not just pass in the `userId` to the route?  We have a better solution.  Once we get our JWT handling in place, we'll be pulling `userId` from the JWT itself.  This provides a more secure solution, as we can trust the JWT has not been tampered with.

Update the `ApiModule` to import the `AuthModule`:
```typescript
import { Module } from '@nestjs/common';
import { ApiController } from './api.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  controllers: [ApiController],
  imports: [AuthModule],
})
export class ApiModule {}
```

Let's test these shell routes.  Ensure the app is running:
```bash
$ npm run start:dev
```

Since these routes are called programmatically, we'll use the commonly available [cURL](https://curl.haxx.se/) library to test them:

```bash
$ # POST to /api/login
$ curl -X POST http://localhost:3000/api/login
$ # result -> {"access_token":"sampletoken"}
$ # GET /api/me
$ curl http://localhost:3000/api/me
$ # result -> {"userId":1,"username":"john","pet":{"name":"alfred","picId":1}}
```

#### Implementing Passport JWT

Passport provides the [passport-jwt](https://github.com/mikenicholson/passport-jwt) strategy for securing RESTful endpoints with JSON Web Tokens.  Start by creating a file called `jwt.strategy.ts` in the `auth` folder, and add the following code:

```typescript
// src/auth/jwt.stratgy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from './auth.service';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtConstants } from './constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub }
  }
}
```

Create the file `constants.ts` in the `auth` folder, and add the following code.  We use this to share the secret between the **Sign** and **Validate** phases of JWT authentication.  Note the security cautions below.

```typescript
export const jwtConstants = {
  secret: 'secretKey',
};
```

We've followed the same recipe described earlier for all Passport strategies.  In this use case with passport-jwt, the strategy requires some initialization, so we do that by passing in an options object in the `super()` call. You can read more about the available options [here](https://github.com/mikenicholson/passport-jwt#configure-strategy).  In our case, these options are:
* jwtFromRequest: supplies the method by which the JWT will be extracted from the `Request`.  We will use the standard approach of supplying a bearer token in the Authorization header of our API requests. Other options are described [here](https://github.com/mikenicholson/passport-jwt#extracting-the-jwt-from-the-request).
* ignoreExpiration: just to be explicit, we choose the default `false` setting, which delegates the responsibility of ensuring that a JWT has not expired to the Passport module.  This means that if our route is supplied with an expired JWT, the request will be denied and a `401 Unauthorized` response sent.  Passport conveniently handles this automatically for us.
* secretOrKey: we are using the expedient option of supplying a symmetric secret for signing the token. Other options, such as a PEM-encoded public key, may be more appropriate for production apps (see [here](https://github.com/mikenicholson/passport-jwt#extracting-the-jwt-from-the-request) for more information).  In any case, as cautioned earlier, **do not expose this secret publicly**.  Instead, use an appropriate secrets vault, environment variable, or configuration service in your production app.

The `validate()` method deserves some discussion. Recall that this method is called by Passport during request authorization. At that point in the process, Passport has verified the JWT's signature and decoded the token.  Passport then invokes our `validate()` method passing that decoded JWT as its single parameter.  Based on the way JWT signing works, we can assume that we're receiving a token that we have previously signed and issued to a valid user.  While we haven't written that code just yet, we can safely make the assumption that this token represents a user we have already validated against our user database.

As a result of all this, our response to the `validate()` callback is trivial: we simply return an object containing the `userId` (note we choose a property name of `sub` to hold our `userId` value to be consistent with JWT standards). Recall again that the purpose of this returned object, within the Passport framework, is so that Passport can build a `user` object and attach it as a property on the `Request` object.

It's also worth pointing out that this framework leaves us room ('hooks' as it were) to inject other business logic into the process.  For example, we **could** do a database lookup in our `validate()` method to extract more information about the user, resulting in a more enriched `user` object being available in our `Request`.  This is also the place we may decide to do further token validation, such as looking up the `userId` in a list of revoked tokens, enabling us to perform token revocation. The model we've implemented here in our sample code is a fast, "stateless JWT" model, where each API call is immediately authorized based on the presence of a valid JWT, and a small bit of information about the requester (its `userId`) is available in our Request pipeline.

#### Implement JWT strategy guards

We're now at the stage where we can implement Guards to:
1. Trigger authentication upon user login (this time, via a RESTful API request)
2. Enforce security on protected REST API endpoints

Let's deal with the login Guard first. We're going to piggyback on the local-storage strategy to allow clients to login with a username and password.  In our first use case (server-side web app), we took steps to ensure that a session was established. To accomplish that, we extended the built-in `AuthGuard` class and overrode the `canActivate()` method (see [Implement guards](#implement-guards)). In this use case, we don't need sessions, so we can use the out-of-the-box `AuthGuard` provided by the passport-local strategy.

Let's update the `POST /api/login` route handler to do so.  Open the `api.controller.ts` file in the `api` folder, and update the `@Post('/login')` route as shown below, as well as the several new imports. While we're here, we're also adding a Guard to the `@Get('/me')` route, and making a change to the `getProfile()` method body.  We'll discuss that next.

```typescript
// src/api/api.controller.ts
import { Controller, Get, Request, Res, Post, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth/auth.service';

@Controller('api')
export class ApiController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(AuthGuard('local'))
  @Post('/login')
  async login(@Request() req, @Res() res: Response) {
    const token = await this.authService.login(req.user);
    res.json(token);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('/me')
  getProfile(@Request() req, @Res() res: Response) {
    res.json(req.user);
  }
}
```

Let's take a closer look at how a  `GET /api/login` request is handled.  We're using the built-in `AuthGuard` provided by the passport-local strategy. This means that:
1. The route handler will only be invoked if the user has successfully authenticated
2. The `req` parameter will contain a `user` property (populated by Passport during authentication)

With this in mind, we can now finally generate a real JWT, and return it in this route, and we're done!  We'll generate the JWT in our `authService`.  Open the `auth.service.ts` file in the `auth` folder, and add the `login()` method, and import the `JwtService` as shown:

```typescript
// sr/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(username, pass): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
```

We're using the `@nestjs/jwt` library, which supplies a `sign()` function to generate our JWT, which we'll return as a simple object with a single `access_token` property.  Don't forget to inject the JwtService provider into the `AuthService`.

We now need to update the `AuthModule` to import the new dependencies and configure the `JwtModule`.  Open up `auth.module.ts` in the `auth` folder and update it to look like this:

```typescript
// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalStrategy } from './local.strategy';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';
import { SessionSerializer } from './session.serializer';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secretOrPrivateKey: jwtConstants.secret,
      signOptions: { expiresIn: '60s' },
    }),
  ],
  providers: [AuthService, LocalStrategy, SessionSerializer, JwtStrategy],
  exports: [AuthService, PassportModule],
})
export class AuthModule {}
```

We configure the `JwtModule` using `register()`, passing in a configuration object. By passing in the same `secret` used when we signed the JWT, we ensure that the **Verify** phase performed by Passport, and the **Sign** phase performed in our `AuthService`, use the same value. See [here](https://github.com/nestjs/jwt/blob/master/README.md) for more on the Nest JwtModule and [here](https://github.com/auth0/node-jsonwebtoken#usage) for more details on the available configuration options.

Ensure the app is running, and test the routes using `cURL`.

```bash
$ # GET /api/me
$ curl http://localhost:3000/api/me
$ # result -> {"statusCode":401,"error":"Unauthorized"}
$ # POST /api/login
$ curl -X POST http://localhost:3000/api/login -d '{"username": "john", "password": "changeme"}' -H "Content-Type: application/json"
$ # result -> {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vybm... }
$ # GET /api/me using access_token returned from previous step as bearer code
$ curl http://localhost:3000/api/me -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vybm..."
$ # result -> {"userId":1}
```

Note that in the `AuthModule`, we configured the JWT to have an expiration of `60 seconds`.  This is probably too short an expiration, and dealing with the details of token expiration and refresh is beyond the scope of this article.  However, we chose that to demonstrate an important quality of JWTs and the Passport JWT strategy.  If you wait 60 seconds after authenticating before attempting a `GET /api/me` request, you'll receive a `401 Unauthorized` response.  This is because Passport automatically checks the JWT for its expiration time, saving you the trouble of doing so in your application.

Our `GET /api/me` method is simply returning `req.user`, which contains just our `userId` property, as expected.  We should really be returning a more complete `user` object.  Let's make that change. We'll need a new method on our `UsersService`.  Update it to look like this:

```typescript
// src/users/users.service.ts
import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private readonly users;

  constructor() {
    this.users = [
      {
        userId: 1,
        username: 'john',
        password: 'changeme',
        pet: { name: 'alfred', picId: 1 },
      },
      {
        userId: 2,
        username: 'chris',
        password: 'secret',
        pet: { name: 'gopher', picId: 2 },
      },
      {
        userId: 3,
        username: 'maria',
        password: 'guess',
        pet: { name: 'jenny', picId: 3 },
      },
    ];
  }

  async findOne(username): Promise<any> {
    return this.users.filter(user => user.username === username)[0];
  }

  async findOneById(id): Promise<any> {
    const found = this.users.filter(user => user.userId === id)[0];
    if (found) {
      const { password, ...result } = found;
      return result;
    }
  }
}
```
In `findOneById()`, we make use of an ES6 spread operator to remove the password before returning the `user` object.

Finally, we update our `ApiController` to use this new find method:

```typescript
// src/api/api.controller.ts
import { Controller, Get, Request, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth/auth.service';
import { UsersService } from '../users/users.service';

@Controller('api')
export class ApiController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  @UseGuards(AuthGuard('local'))
  @Post('/login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('/me')
  getProfile(@Request() req) {
    return this.usersService.findOneById(req.user.userId);
  }
}
```

Now, when we run our `GET /api/me` request (don't forget to authenticate again, and pass in the newly minted access_token), we get these results:

```bash
$ # GET /api/me using access_token returned from previous step as bearer code
$ curl http://localhost:3000/api/me -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vybm..."
$ # result -> {"userId":1,"username":"john","pet":{"name":"alfred","picId":1}}
```

We've now completed our JWT authentication implementation.  JavaScript clients (such as Angular/React/Vue), and other JavaScript apps, can now authenticate and communicate securely with our API Server.

#### Additional considerations

##### Default strategy

In our `ApiController`, we pass the name of the strategy in the `@AuthGuard()` decorator.  We need to do this because we've introduced **two** Passport strategies (passport-local and passport-jwt), both of which supply implementations of various Passport components. Passing the name disambiguates which implementation we're linking to.  When multiple strategies are included in an application, we can declare a default strategy so that we no longer have to pass the name in the `@AuthGuard` decorator if using that default strategy.  Here's how to register a default strategy when importing the `PassportModule`.  This code would go in the `AuthModule`:

```typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { HttpStrategy } from './http.strategy';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    UsersModule,
  ],
  providers: [AuthService, HttpStrategy],
  exports: [PassportModule, AuthService]
})
export class AuthModule {}
```

##### Customize Passport
Any standard Passport customization options can be passed the same way, using the `register()` method.  The available options depend on the strategy being implemented.  For example:

```typescript
PassportModule.register({ session: true });
```

##### Named strategies
When implementing a strategy, you can provide a name for it by passing a second argument to the `PassportStrategy` function. If you don't do this, each strategy will have a default name (e.g., 'jwt' for jwt-strategy):

```typescript
export class JwtStrategy extends PassportStrategy(Strategy, 'myjwt')
```

Then, you refer to this via a decorator like `@AuthGuard('myjwt')`.

#### GraphQL

In order to use an AuthGuard with [GraphQL](https://docs.nestjs.com/graphql/quick-start), extend the built-in AuthGuard class and override the getRequest() method.

```typescript
@Injectable()
export class GqlAuthGuard extends AuthGuard('jwt') {
  getRequest(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req;
  }
}
```

To use the above construct, be sure to pass the request (`req`) object as part of the context value in the GraphQL Module settings:

```typescript
GraphQLModule.forRoot({
  context: ({ req }) => ({ req }),
});
```