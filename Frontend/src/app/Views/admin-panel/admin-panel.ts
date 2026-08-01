import { Component, OnInit, ChangeDetectorRef , signal} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { UserService } from '../../Services/UserService';
import { LayoutService } from '../../Services/LayoutService';
import { getCurrentUserDto } from '../../Dto/getCurrentUserDto';
import { EventsNavigationService }from '../../RootingServices/EventsNavigationService'
import { UserNavigationService }from '../../RootingServices/UserNavigationService'

@Component({
  selector: 'app-admin-panel',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './admin-panel.html',
  styleUrl: './admin-panel.css',
})
export class AdminPanel {

  constructor(
    private eventsNavigtionService: EventsNavigationService,
  ){}

  seedData() {
    this.eventsNavigtionService.seedDatabase()
  }
}
