import { ComponentFixture, TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { ChangeDetectorRef } from '@angular/core';
import { NEVER, of, throwError } from 'rxjs';
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

import { SubBoughtEventInfo } from './sub-bought-event-info';
import { EventService } from '../../../Services/EventService';
import { getEventTicketWithQrDto } from '../../../Dto/getEventQrCodeInfoDto';

describe('SubBoughtEventInfo', () => {
  let component: SubBoughtEventInfo;
  let fixture: ComponentFixture<SubBoughtEventInfo>;
  let eventService: { getTicketsWithQr: ReturnType<typeof vi.fn> };

  const mockEvent = {
    typeOfEvent: 'Koncert',
    nameOfEvent: 'Summer Festival',
    qrCode: 'mock-qr-code',
    startOfEvent: '2026-08-15T18:00:00',
    nameOfClub: 'Klub Muzyczny',
    address: 'ul. Kwiatowa 10',
    city: 'Bielsko-Biała',
    urlOfEvent: 'https://example.com/event',
  } as unknown as getEventTicketWithQrDto;

  beforeEach(async () => {
    eventService = {
      getTicketsWithQr: vi.fn().mockReturnValue(of(mockEvent)),
    };

    await TestBed.configureTestingModule({
      imports: [SubBoughtEventInfo],
      providers: [
        {
          provide: MAT_DIALOG_DATA,
          useValue: { eventId: 1 },
        },
        {
          provide: MatDialogRef,
          useValue: { close: vi.fn() },
        },
        {
          provide: EventService,
          useValue: eventService,
        },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(SubBoughtEventInfo);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should create', () => {
    fixture.detectChanges();

    expect(component).toBeTruthy();
  });

  it('should get event ID from dialog data', () => {
    fixture.detectChanges();

    expect(component.eventId).toBe(1);
  });

  it('should load event details on initialization', () => {
    fixture.detectChanges();

    expect(eventService.getTicketsWithQr).toHaveBeenCalledWith(1);
    expect(component.event).toEqual(mockEvent);
    expect(component.loading).toBe(false);
  });

  it('should display event details', () => {
    fixture.detectChanges();

    const element: HTMLElement = fixture.nativeElement;

    expect(element.querySelector('.dialog-title')?.textContent).toContain('Summer Festival');

    expect(element.querySelector('.dialog-badge')?.textContent).toContain('Koncert');

    expect(element.querySelector('.qr-code')).not.toBeNull();

    expect(element.querySelector('.dialog-link')?.getAttribute('href')).toBe(
      'https://example.com/event',
    );

    expect(element.textContent).toContain('Klub Muzyczny');
    expect(element.textContent).toContain('ul. Kwiatowa 10');
    expect(element.textContent).toContain('Bielsko-Biała');
  });

  it('should display loading indicator while waiting for the response', () => {
    eventService.getTicketsWithQr.mockReturnValue(NEVER);

    fixture.detectChanges();

    expect(component.loading).toBe(true);

    const element: HTMLElement = fixture.nativeElement;

    expect(element.querySelector('.dialog-loading')).not.toBeNull();
  });

  it('should handle an error when loading event details', () => {
    const error = new Error('Request failed');
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});

    eventService.getTicketsWithQr.mockReturnValue(throwError(() => error));

    fixture.detectChanges();

    expect(component.loading).toBe(false);
    expect(component.event).toBeUndefined();
    expect(consoleSpy).toHaveBeenCalledWith(error);
    expect(alertSpy).toHaveBeenCalledWith('Nie udało się getEvents');
  });

  it('should hide optional event information when fields are missing', () => {
    const minimalEvent = {
      nameOfEvent: 'Test Event',
    } as getEventTicketWithQrDto;

    eventService.getTicketsWithQr.mockReturnValue(of(minimalEvent));

    fixture.detectChanges();

    const element: HTMLElement = fixture.nativeElement;

    expect(element.querySelector('.dialog-title')?.textContent).toContain('Test Event');

    expect(element.querySelector('.qr-box')).toBeNull();
    expect(element.querySelector('.dialog-badge')).toBeNull();
    expect(element.querySelector('.dialog-link')).toBeNull();
  });
});
