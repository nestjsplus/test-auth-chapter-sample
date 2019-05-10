### Authentication

Authentication is an **essential** part of most applications. There are a lot of different approaches, strategies, and ways to handle authentication. The approach taken for any project depends on its particular application requirements.  This chapter provides several approaches to authentication that can be adapted to a variety of different requirements.

[Passport](https://github.com/jaredhanson/passport) is the most popular node.js authentication library, well-known by the community and successfully used in many production applications. It's straightforward to integrate this library with a **Nest** application using the built-in `@nestjs/passport` module.

In this chapter, we'll consider two representative use cases, and implement a complete end-to-end authentication solution for each:
* Traditional web application with server-side template-driven HTML pages
* API Server that accepts REST/HTTP requests and returns JSON responses

#### Server-side web application use case

Let's flesh out our requirements. For this use case, users will authenticate with a username and password. Once authenticated, the server will utilize Express sessions so that the user remains "logged in" until they choose to log out.  We'll set up a protected route that is accessible only to an authenticated user.

 We start by installing the required packages, and building our basic routes. As a side note, for **any** Passport strategy you choose (there are many available [here](http://www.passportjs.org/packages/)), you'll always need the `@nestjs/passport` and `passport` packages. Then, you'll need to install the strategy-specific package (e.g., `passport-jwt` or `passport-local`) that scaffolds the particular authentication strategy you are building.

Passport provides a [passport-local](https://github.com/jaredhanson/passport-local) package that implements a username/password authentication strategy, which suits our needs for this use case. Since we are rendering some basic HTML pages, we'll also install the versatile and popular [express-handlebars](https://github.com/ericf/express-handlebars) package to make that a little easier.  To support sessions and convenient user feedback during login, we'll also utilize the express-session and connect-flash packages. With these basic requirements in mind, we can now start by scaffolding a brand new Nest application, and installing the dependencies:

```bash
$ nest new auth-sample
$ cd auth-sample
$ npm install --save @nestjs/passport passport passport-local express-handlebars express-session connect-flash @types/express
```

> warning **Notice** NOTE TO REVIEWERS: We haven't typically included front-end code in the documentation so far.  I think it is useful in this case, as a goal is to provide an end-to-end "template" that users can build from, and to add "depth" to the documentation, especially in areas we know people have struggled.  I would like to get feedback on this.  As well, there's a decision as to whether to include the front-end code in-line in the document, or refer the reader to a repo.  As we can always remove it after the fact, I'm including it in-line in this draft so you can see it and comment.

> warning **Notice** On a related note, this chapter necessarily diverges from "cats", and as such, I'm proposing a complete repo that can be cloned. Users can refer directly to the repo to run the code documented here.

Let's start by building the templates we'll use to exercise our authentication subsystem.  Following a standard MVC type project structure, create the following folder structure (i.e., the `public` folder and its sub-folders):

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

Now, we'll create the following handlebars templates, and configure Nest to use express-handlebars as our view engine.  Refer [here](https://handlebarsjs.com/) for more on the handlebars template language.

##### Main layout

Create `main.hbs` in the layouts folder, and add the following code.  This is the outermost container for our views.  Note the `{{ '{' }}{{ '{' }}{{ '{' }} body {{ '}' }}{{ '}' }}{{ '}' }}` line, which is where each individual view is inserted.  This structure allows us to set up global styles.  In this case, we're taking advantage of Google's well-known [material design lite](https://github.com/google/material-design-lite) component library to style our minimal UI. All of those dependencies are taken care of in the `<head>` section of our layout.

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

Create `home.hbs` in the views folder, and add the following code.  This is the page users land on after authenticating.
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

Create `login.hbs` in the views folder, and add the following code.  This is the login form.
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

Create `profile.hbs` in the views folder and add the following code.  This page displays details about the logged in user.  It's rendered on our protected route.
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

#### Set up view engine
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

#### Authentication routes
The final step in this section is setting up our routes.  Modify `src\app.controller.ts` so that it looks like this:
```typescript
// src/app.controller.ts
import { Controller, Get, Post, Request } from '@nestjs/common';
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

At this point, you should be able to browse to <a href="http://localhost:3000/">http://locahost:3000</a> and click through the basic UI.

#### Implementing Passport strategies

We're now ready to implement the authorization feature. Let's start with an overview of the process used for **any** Passport strategy.  It's helpful to think of Passport as a mini framework in itself. The beauty of the framework is that it abstracts authentication into a few basic things that you customize based on the strategy you're implementing.  It's like a framework because you configure it by supplying custom code in the form of callbacks, which Passport calls at the appropriate time.  The nest-passport module wraps this framework in a Nest style package.  In vanilla passport, you configure a strategy by providing two things:
1. A set of options that are specific to that strategy.
2. A "verify callback", which is where you tell Passport how to interact with your user store (where you manage user accounts) and verify whether a user exists (or possibly create a new user), and whether their credentials are valid.

In Nest, you achieve these functions by extending the `PassportStrategy` class.  You pass the strategy options (item 1 above) by calling the `super()` method in your subclass.  You provide the verify callback (item 2 above) by implementing a `validate` method in your subclass.

As mentioned, we'll utilize the passport-local strategy for this use-case.  We'll do that below.  Start by generating an `auth module` and in it, an `auth service`:

```bash
$ nest g module auth
$ nest g service auth
```

As we implement the `auth service`, you'll see that we'll also want to have a `users service`, so let's generate that module and service now:

```bash
$ nest g module users
$ nest g service users
```

Replace the default contents of these generated files as shown below.

In our prototype, the `UsersService` simply maintains a hard-coded in-memory list of users, and a method to retrieve one by username.  In a real app, this is where you'd build your user model and persistence layer, using your library of choice (e.g., TypeORM, Sequelize, Mongoose, etc.).

```typescript
// src/users/users.service.ts
import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private readonly users;

  constructor() {
    this.users = [
      {
        username: 'john',
        password: 'changeme',
        pet: { name: 'alfred', picId: 1 },
      },
      {
        username: 'chris',
        password: 'secret',
        pet: { name: 'gopher', picId: 2 },
      },
      {
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

In the `UsersModule`, the only change is to add the `UsersService` to the exports array of the `@Module` decorator so that it is visible outside this module (we'll want to use it in our `AuthService`).
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

Our `AuthService` has the job of retrieving a user and verifying the password.  Of course in a real application, you wouldn't store a password in plain text. You'd instead use a library like [bcrypt](https://github.com/kelektiv/node.bcrypt.js#readme), with a salted one-way hash algorithm. With that approach, you'd only store hashed passwords, and then compare the stored password to a hashed version of the **incoming** password, thus never storing or exposing user passwords in plain text. To keep our prototype simple, we violate that absolute mandate and use plain text.  **Don't do this in your real app!**

We'll call into our `validateUser()` method from our Passport local strategy subclass in a moment. The Passport library expects us to return a full user if the validation succeeds, or a null if it fails (failure is defined as either the user is not found, or the password does not match). Upon successful validation, Passport then takes care of a few details for us, which we'll explore later on in the Sessions section.

```typescript
// src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async validateUser(username, password): Promise<any> {
    const user = await this.usersService.findOne(username);
    return user && user.password === password ? user : null;
  }
}
```

And finally, we just need to update our `AuthModule` so it imports the `UsersModule`.

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
Our app will function now, but remains slightly broken until we complete a few more steps.  You can navigate to <a href="http://localhost:3000/">http://locahost:3000</a> and still move around without logging in (after all, we haven't implemented our Passport local strategy yet.  We'll get there momentarily).  Notice that if you **do** login (refer to the `UsersService` for username/passwords you can test with), the profile page now provides some (but not all) information about a "logged in" user.

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

We followed the recipe described earlier.  In our use-case with passport-local, there are no configuration options, so our constructor simply calls `super()`, without an options object.  (Later, we'll see how to pass options in the call to `super()`).  We've also implemented the `validate()` method. Most of the work is done in our `AuthService` (and in turn, in our `UserService`), so this method is quite straightforward. All `validate()` methods will follow a similar pattern.  If a user is found and valid, it should be returned so Passport can do some further housekeeping.  If it's not found, we throw an exception and let our <a href="exceptions">exceptions layer</a> handle it.  It turns out that the only really significant difference for each strategy is **how** you determine if a user exists and is "valid".  For example, in a JWT strategy, we'll verify that a token is valid (and possibly, depending on requirements, whether the "userId" carried in the decoded token matches a record in our user database).  Hence, this pattern of sub-classing and implementing strategy-specific validation is elegant and extensible.

With the strategy in place, we have a few more tasks to complete:
1. Create Guards we can use to decorate routes so that the configured Passport middleware is invoked
2. Add `@UseGuards()` decorators as needed
3. Implement sessions so that users can stay logged in across requests
4. Configure Nest to use Passport
5. Add a little polish to the user experience

Let's get started.  For the following sections, we'll want to adhere to a best practice project structure, so let's start by creating a few more folders.  Under `src`, create a `common` folder.  Inside `common`, create `filters` and `guards` folders.  Our structure now looks like this:

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
1. the user is **not** logged in (not authenticated)
2. the user **is** logged in (is authenticated)

In the first case, we want to restrict the routes the user can access (deny access to restricted routes).  We'll use Guards in their familiar capacity to handle this function.  We'll do this through a standard, user-defined `AuthenticatedGuard` which we'll build shortly.  We also need to handle the authentication step (invoking that strategy we just built) when the unauthenticated user attempts to login.  Looking at our UX, it's easy to se that we'll handle this via a `POST` request on our `/login` route. This raises the question: how exactly do we invoke the Passport local strategy in that route?

The answer is: using another Guard.  Similar to the way we extended the `PassportStrategy` class in the last section, we'll start with a default `AuthGuard` provided in the `@nestjs/passport` package, and extend it as needed.  We'll decorate our `POST /login` route with this extended `AuthGuard` to invoke our Passport local strategy.

The second case (logged in user) simply relies on the same standard user-defined `AuthenticatedGuard` to enable the logged in user to access protected routes.

Let's cover the `AuthGuard` first. Create a file called `login.guard.ts` in the `guards` folder:`

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

There's lots going on in these few lines of code, so let's walk through it.
* Our Passport local strategy has a default name of 'local'.  We reference that name in the `extends` clause of the LoginGuard we are defining to tie our custom Guard to the code supplied by the `pasport-local` package.
* As with all Guards, the primary method we define/override is `canActivate()`, which is what we do now.
* The body of `canActivate()` is setting up an Express session.  Here's what's happening:
    * we call `canActivate()` on the super class, as we normally would in extending a super class method, saving the result. Our super class provides the framework for invoking our Passport local strategy.  Recall from the [Guards]() chapter that `canActivate()` returns a boolean indicating whether or not the target route will be called.  When we get here, Passport will have run the previously configured strategy and will return a boolean to indicate whether or not the user has successfully authenticated.  Here, we stash the result so we can do a little more processing before finally returning.
    * the key step for starting a session is to now invoke the `logIn()` method on our super-class, passing in the current request.  This actually calls a special method that Passport automatically added to our Express `Request` object during the previous step.  See [here](http://www.passportjs.org/docs/configure/) and [here](http://www.passportjs.org/docs/login/) for more on Passport sessions and these special methods.
    * the Express session has now been setup, and we can return our `canActivate()` result, allowing only authenticated users to continue.

#### Sessions

Now that we've introduced sessions, there's one additional detail we need to take care of.  Sessions are a way of associating a unique user with some server-side state information about that user.

> warning **Notice** TBD: Details on Passport sessions (deferred for this draft).  Seems important to provide context for how to implement the serialize/deserialize protocol.  Sadly, Passport docs don't have much here.

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

Now let's create our `AuthenticatedGuard`.  This is a traditional Guard, as covered in the <a href="guards">Guards</a> chapter. Its role is simply to protect certain routes.
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

The only thing to point out here is that in order to determine whether a user is authenticated or not, we simply test for the presence of a `user` property on the `Request` object.  The reason this works is that Passport, upon successful authentication, attaches this property to the `Request` object for us.

#### Configure Nest to use features

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

Here, we've added the session and passport support to our Nest app.  As always, be sure to keep secrets out of your source code (**don't put your session secret in the code, as we did here; use environment variables or a config module instead**).  Note carefully that the order is important (register the session middleware first, then initialize passport, then configure passport to use sessions).  We'll see the use of the `flash` feature in a few minutes.

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

Above, we've imported our two new Guards and applied them appropriately.  We use the `LoginGuard` on our `POST /login` route to initiate the authentication sequence in the Passport local strategy.  We use `AuthenticateGuard` on our protected routes to ensure they aren't accessible to unauthenticated users.

We're also taking advantage of the Passport feature that automatically stores our `User` object on the `Request` object as `req.user`.  With this handy feature, we can pass a variable into our handlebars templates (e.g., `res.render('profile', {{ '{' }} user: req.user {{ '}' }})`) to customize their content.

Finally, we have added the call to `req.logout()` in our `logout` route.  This relies on the Passport logout function, which, similar to the `logIn()` method we discussed earlier in the Sessions section, has been added by Passport automatically upon successful authentication.  When we invoke `logout()`, Passport tears down our session for us.

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

The only new element here from what's covered in <a href="exception-filters">Filters</a> is the use of connect-flash.  If a route returns either a `UnauthorizedException` or a `ForbiddenException`, we redirect to the root route with `response.redirect('/')`.  We also use connect-flash to store a message in Passport's session.  This mechanism allows us to temporarily persist a message upon redirect.  Passport and connect-flash automatically take care of the details of storing, retrieving, and cleaning up those messages.

The final touch is to display the flash message in our handlebars template.  Update `app.controller.ts` to look like this.  In this update, we're adding the `AuthExceptionFilter` and adding the flash parameters to our index (`/`) route.

```typescript
// src/app.controller.tas
// src/app.controller.ts
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