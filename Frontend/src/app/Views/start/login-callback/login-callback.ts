import { Component, OnInit, ChangeDetectorRef, signal, inject } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../../Services/UserService';
import { AuthService } from '../../../Services/AuthService';
import { EventsNavigationService } from '../../../RootingServices/EventsNavigationService';
import { UserNavigationService } from '../../../RootingServices/UserNavigationService';

@Component({
  selector: 'app-login-callback',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './login-callback.html',
  styleUrl: './login-callback.css',
})
export class LoginCallback implements OnInit {
  userEmailData: typeof this.authService.userEmail;
  userRoleData = signal(localStorage.getItem('userRole') ?? '');

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private userService: UserService,
    private eventsNavigtionService: EventsNavigationService,
    private userNavigationService: UserNavigationService,
    private authService: AuthService,
    private cdr: ChangeDetectorRef,
  ) {
    this.userEmailData = this.authService.userEmail;
  }

  ngOnInit(): void {
    this.generateJWT();
  }

  generateJWT() {
    const emailFromUrl = this.route.snapshot.queryParamMap.get('email');
    const emailFromStorage = localStorage.getItem('email');

    const roleFromUrl = this.route.snapshot.queryParamMap.get('userRole');
    const roleFromStorage = localStorage.getItem('userRole');

    const email = emailFromUrl ?? emailFromStorage;
    const role = roleFromUrl ?? roleFromStorage;

    if (email && role) {
      this.authService.setAuthData(email, role);
    }
  }

  adminView() {
    return this.eventsNavigtionService.adminPanel();
  }

  isLogged() {
    return this.authService.isLogged();
  }

  isAdmin() {
    return this.authService.isAdmin();
  }

  eventsView() {
    this.eventsNavigtionService.goToEvents();
  }

  searchAndImportView() {
    this.eventsNavigtionService.searchAndDownloadEvents();
  }

  userBoughtTickets() {
    this.userNavigationService.userBoughtTickets();
  }

  editCurrentUser() {
    this.userNavigationService.editCurrentUser();
  }

  getUserBookmarks() {
    this.userNavigationService.editCurrentUser();
  }

  userBookmarkedEvents(){
    this.userNavigationService.userBookmarkedEvents();
  }
}
