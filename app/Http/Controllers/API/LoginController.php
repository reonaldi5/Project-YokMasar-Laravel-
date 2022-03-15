<?php

namespace App\Http\Controllers;
namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Laravel\Fortify\Rules\Password;


use Illuminate\Http\Request;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(),[
                'email' => 'required|email',  //'email|required',
                'password' => 'required',  //'password|required',
            ]);

            $credentials = request(['email','password']);
            if (Auth::attempt($credentials)) {
                // $user = Auth::user();
                $request->session()->regenerate(); //tambahan dr dokumentasi
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }

            dd($credentials);

            $user = User::where('email', $validator->email)->first();
            dd($user);

            if(Hash::check($validator->password, $user->password, [])) {
                throw new \Exception('Invalid Credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'user' => $user,
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
            ], 'Authenticated');
            
        } catch (Exception $error) {

            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error

            ], 'Authentication Failed', 500);
        }
    }

}
