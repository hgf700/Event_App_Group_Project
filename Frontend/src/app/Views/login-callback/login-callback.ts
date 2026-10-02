import { Component, OnInit, ChangeDetectorRef, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { LayoutService } from '../../Services/LayoutService';
import { EventsNavigationService } from '../../RootingServices/EventsNavigationService';
import { UserNavigationService } from '../../RootingServices/UserNavigationService';

@Component({
  selector: 'app-login-callback',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './login-callback.html',
  styleUrl: './login-callback.css',
})
export class LoginCallback implements OnInit {
  userEmailData = signal(localStorage.getItem('email') ?? '');

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private userService: UserService,
    private layoutService: LayoutService,
    private eventsNavigtionService: EventsNavigationService,
    private userNavigationService: UserNavigationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.generateJWT();
  }

  generateJWT() {
    const tokenFromUrl = this.route.snapshot.queryParamMap.get('jwt');
    const tokenFromStorage = localStorage.getItem('jwt');

    const emailFromUrl = this.route.snapshot.queryParamMap.get('email');
    const emailFromStorage = localStorage.getItem('email');

    const roleFromUrl = this.route.snapshot.queryParamMap.get('userRole');
    const roleFromStorage = localStorage.getItem('userRole');

    console.log({
      tokenFromUrl,
      tokenFromStorage,
      emailFromUrl,
      emailFromStorage,
      roleFromUrl,
      roleFromStorage,
    });

    if (!tokenFromUrl && !tokenFromStorage && !emailFromUrl && !emailFromStorage 
      && !roleFromUrl && !roleFromStorage
    ) {
      console.error('Brak tokena – użytkownik niezalogowany');
      return;
    }

    this.layoutService.setUserEmail(localStorage.getItem('email') ?? '');
  }

  adminView() {
    this.eventsNavigtionService.adminPanel();
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
}
