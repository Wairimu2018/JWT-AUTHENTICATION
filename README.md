# README

Ruby on Rails API Simple authentication with JWT
#
ruby
#
rails
#
jwt
#
api
auth flow chart

Implementing a simple JWT authentication in a rails application with less configuration. The idea is to have a middleware that checks token in the request headers object to verify token before allowing user access to secure controller methods.

Here we've sessions controller responsible for LOGIN and SIGNUP, and a todos controller to perform CRUD.

but first, let's create a new rails API by running
rails new todoApi --api 
and generate our models
#Users model 

rails generate model user email:string password:string

#Todos model 

rails generate model todo title:string 

# run migration 

rails db:migrate
and install jwt by adding
gem 'jwt'
to Gemfile

and inside application_controller.rb we define our authentication methods since all controllers inherit from application controller
class ApplicationController < ActionController::API
  SECRET = "yoursecretword"

  def authentication
    # making a request to a secure route, token must be included in the headers
    decode_data = decode_user_data(request.headers["token"])
    # getting user id from a nested JSON in an array.
    user_data = decode_data[0]["user_id"] unless !decode_data
    # find a user in the database to be sure token is for a real user
    user = User.find(user_data&.id)

    # The barebone of this is to return true or false, as a middleware
    # its main purpose is to grant access or return an error to the user

    if user
      return true
    else
      render json: { message: "invalid credentials" }
    end
  end

  # turn user data (payload) to an encrypted string  [ A ]
  def encode_user_data(payload)
    token = JWT.encode payload, SECRET, "HS256"
    return token
  end

  # turn user data (payload) to an encrypted string  [ B ]
  def encode_user_data(payload)
    JWT.encode payload, SECRET, "HS256"
  end

  # decode token and return user info, this returns an array, [payload and algorithms] [ A ]
  def decode_user_data(token)
    begin
      data = JWT.decode token, SECRET, true, { algorithm: "HS256" }
      return data
    rescue => e
      puts e
    end
  end

  # decode token and return user info, this returns an array, [payload and algorithms] [ B ]
  def decode_user_data(token)
    begin
      JWT.decode token, SECRET, true, { algorithm: "HS256" }
    rescue => e
      puts e
    end
  end
end

now let's add a few configuration to our routes and sessions controller

in routes.rb
Rails.application.routes.draw do
  post "/login", to: "sessions#login"
  post "/signup", to: "sessions#signup"

  resources :todos

end
in sessions_controller.rb
class SessionsController < ApplicationController
  def signup
    user = User.new(email: param[:email], password: password[:password])

    # if user is saved
    if user.save
      # we encrypt user info using the pre-define methods in application controller
      token = encode_user_data({ user_data: user.id })

      # return to user
      render json: { token: token }
    else
      # render error message
      render json: { message: "invalid credentials" }
    end
  end

  def login
    user = User.find_by(email: param[:email])

    # you can use bcrypt to password authentication
    if user && user.password == param[:password]

      # we encrypt user info using the pre-define methods in application controller
      token = encode_user_data({ user_data: user.id })

      # return to user
      render json: { token: token }
    else
      render json: { message: "invalid credentials" }
    end
  end
end 
we can now secure controller methods by using a controller callback and authentication method in application_controller.rb
class TodosController < ApplicationController

# authentication is the method we define in application_controller.rb to check request.headers['token']

  before_action :authentication

  # GET /todos
  def index
    @todos = Todo.all

    render json: @todos
  end
end
easy peasy..