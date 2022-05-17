import {User} from "../models/user.model";
import {AuthenticationService} from "./authentication.service";
import {HttpClient, HttpHeaders} from "@angular/common/http";


export abstract class RequestBaseService {

  protected currentUser: User = new User;

  protected constructor(protected authenticationService: AuthenticationService, protected http: HttpClient) {
    this.authenticationService.currentUser.subscribe(data => {
      this.currentUser = data;
    });
  }

  get getHeaders(): HttpHeaders {
    return new HttpHeaders(
      {
        authorization: 'Bearer ' + this.currentUser?.accessToken,
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        "Access-Control-Allow-Headers": "X-Requested-With, content-type, Authorization"
      }
    );
  }
}