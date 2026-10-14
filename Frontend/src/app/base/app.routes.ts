import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginCallback } from '../Views/start/login-callback/login-callback';
import { RegisterUser } from '../Views/user/register-user/register-user';
import { PaymentStatus } from '../Views/event/payment-status/payment-status';
import { SearchAndImportEvents } from '../Views/event/search-and-import-events/search-and-import-events';
import { EditUser } from '../Views/user/edit-user/edit-user';
import { EditUserPassword } from '../Views/user/edit-user-password/edit-user-password';
import { AdminPanel } from '../Views/admin/admin-panel/admin-panel';
import { Events } from '../Views/admin/events/events';
import { BlockedUsers } from '../Views/admin/blocked-users/blocked-users';
import { Tickets } from '../Views/admin/tickets/tickets';
import { Users } from '../Views/admin/users/users';
import { Dashbord } from '../Views/admin/dashbord/dashbord';
import { Home } from '../Views/start/home/home';
import { LoginUser } from '../Views/user/login-user/login-user';
import { SeedDatabase } from '../Views/admin/seed-database/seed-database';
import { GetEvents } from '../Views/event/get-events/get-events';
import { SubEventDetails } from '../Views/event/sub-event-details/sub-event-details';
import { UserTickets } from '../Views/user/user-tickets/user-tickets';
import { EditUserEmail } from '../Views/user/edit-user-email/edit-user-email';
import { authGuard } from '../helpers/authGuard';
import { ErrorPage } from '../Views/http-status/error-page/error-page';
import { Forbidden } from '../Views/http-status/forbidden/forbidden';
import { NotFound } from '../Views/http-status/not-found/not-found';
import { ServerError } from '../Views/http-status/server-error/server-error';
import { Unauthorised } from '../Views/http-status/unauthorised/unauthorised';

export const routes: Routes = [
  { path: '', component: Home },
  { path: 'login-user', component: LoginUser },
  { path: 'register-user', component: RegisterUser },
  { path: 'login-callback', component: LoginCallback },
  { path: 'seed-database',canActivate: [authGuard], component: SeedDatabase },
  { path: 'get-events',canActivate: [authGuard], component: GetEvents },
  { path: 'sub-event-details/:id',canActivate: [authGuard], component: SubEventDetails },
  { path: 'payment-status',canActivate: [authGuard], component: PaymentStatus },
  { path: 'search-and-import-events',canActivate: [authGuard], component: SearchAndImportEvents },
  { path: 'user-tickets',canActivate: [authGuard], component: UserTickets },
  { path: 'edit-user',canActivate: [authGuard], component: EditUser },
  { path: 'edit-user-email',canActivate: [authGuard], component: EditUserEmail },
  { path: 'edit-user-password',canActivate: [authGuard], component: EditUserPassword },
  {
    path: 'admin-panel',
    component: AdminPanel,
    children: [
      { path: '',canActivate: [authGuard], component: Dashbord },
      { path: 'events',canActivate: [authGuard], component: Events },
      { path: 'blocked-users',canActivate: [authGuard], component: BlockedUsers },
      { path: 'tickets',canActivate: [authGuard], component: Tickets },
      { path: 'users',canActivate: [authGuard], component: Users },
    ],
  },
  { path: 'error-page', component: ErrorPage },
  { path: 'forbidden', component: Forbidden },
  { path: 'not-found', component: NotFound },
  { path: 'server-error', component: ServerError },
  { path: 'unauthorised', component: Unauthorised },
  
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
