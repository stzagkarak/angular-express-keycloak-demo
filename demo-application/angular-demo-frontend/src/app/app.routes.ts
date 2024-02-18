import { Routes } from '@angular/router';
import { WelcomeComponent } from './pages/welcome/welcome.component';
import { FailComponent } from './pages/fail/fail.component';

export const routes: Routes = [
    {path: "", component: WelcomeComponent},
    {path: "welcome", component: WelcomeComponent},
    {path: "fail", component: FailComponent},
    {path: "**", component: FailComponent}
];
