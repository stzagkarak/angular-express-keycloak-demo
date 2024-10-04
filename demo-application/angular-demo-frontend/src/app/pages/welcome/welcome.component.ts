import { Component, OnInit } from '@angular/core';
import { HttpService } from '../../http.service';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-welcome',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './welcome.component.html',
  styleUrl: './welcome.component.css'
})
export class WelcomeComponent implements OnInit {

  constructor(private httpService: HttpService, 
    private route: ActivatedRoute
  ) {}

  loginText="No Info"
  greenOn = false;
  redOn = false;

  userInfo = "No Info";
  redUserInfo = false;

  admActionOutput = "";
  greenAction = false;
  redAction = false;

  actions = "";
  userType = "";

  ngOnInit() {
    this.actions = this.route.snapshot.queryParamMap.get('actions') ?? "";
    this.userType = this.route.snapshot.queryParamMap.get('userType') ?? "";

    // if actions is set to true, immediatly try to login
    if(this.actions == "login") {

      // if provider, append userType param in the login call
      if(this.userType == "provider")
        return this.httpService.login(true)
      else 
        return this.httpService.login(false)
    }

    // type of user is provider
    if(this.userType) {
      // call backend to check if this is the first time the provider logs in. 
      // if true, navigate to info form.
      // else ignore 
      console.log(this.userType)
    }
  }

  checkLoginStatus() {
    this.httpService.loginStatus().subscribe({
      next: (ret:any)=> {
        if(ret.status === 0) {
          this.loginText = "Not Logged In";
          this.greenOn = false;
          this.redOn = true;
        }
        else if(ret.status === 1) {
          this.loginText = "Logged In";
          this.greenOn = true;
          this.redOn = false;
        }
      }
    })
  }

  login(isProvider: Boolean) {
    return this.httpService.login(isProvider)
  }

  register(isProvider: Boolean) {
    return this.httpService.register(isProvider)
  }

  logout() {
    return this.httpService.logout()
  }

  getUserInfo() {
    return this.httpService.getUserInfo().subscribe({
      next: (ret)=> {
        this.userInfo = JSON.stringify(ret)
        this.redUserInfo = false;
      },
      error: (err)=> {
        this.userInfo = "Not Authenticated"
        this.redUserInfo = true;
      }
    })
  }

  performAdminAction() {
    return this.httpService.performAdminAction().subscribe({
      next: (ret)=> {
        this.admActionOutput = JSON.stringify(ret);
        this.greenAction = true;
        this.redAction = false;
      },
      error: (err)=> {
        this.admActionOutput = "Not Authenticated"
        this.redAction = true;
        this.greenAction = false;
      }
    })
  }
}
