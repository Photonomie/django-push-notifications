from django.apps import apps
from django.contrib import admin, messages
from django.utils.translation import ugettext_lazy as _
from django.utils.text import slugify
from .gcm import GCMError
from .models import APNSDevice, GCMDevice, get_expired_tokens
from .settings import PUSH_NOTIFICATIONS_SETTINGS as SETTINGS
from .apns import apns_get_app_names


User = apps.get_model(*SETTINGS["USER_MODEL"].split("."))


class DeviceAdmin(admin.ModelAdmin):
	list_display = ("__str__", "device_id", "user", "active", "date_created")
	list_filter = ("active", )
	actions = ("send_message", "send_bulk_message", "prune_devices", "enable", "disable")
	raw_id_fields = ("user", )

	if hasattr(User, "USERNAME_FIELD"):
		search_fields = ("name", "device_id", "user__%s" % (User.USERNAME_FIELD))
	else:
		search_fields = ("name", "device_id")

	def send_messages(self, request, queryset, bulk=False, app_name=None):
		"""
		Provides error handling for DeviceAdmin send_message and send_bulk_message methods.
		"""
		ret = []
		errors = []
		r = ""

		for device in queryset:
			try:
				if bulk:
					r = queryset.send_message("Test bulk notification", app_name=app_name)
				else:
					r = device.send_message("Test single notification", app_name=app_name)
				if r:
					ret.append(r)
			except GCMError as e:
				errors.append(str(e))

			if bulk:
				break

		if errors:
			self.message_user(request, _("Some messages could not be processed: %r" % (", ".join(errors))), level=messages.ERROR)
		if ret:
			if not bulk:
				ret = ", ".join(ret)
			if errors:
				msg = _("Some messages were sent: %s" % (ret))
			else:
				msg = _("All messages were sent: %s" % (ret))
			self.message_user(request, msg)

	def send_message(self, request, queryset):
		self.send_messages(request, queryset)
	send_message.short_description = _("Send test message")

	def send_bulk_message(self, request, queryset):
		self.send_messages(request, queryset, True)
	send_bulk_message.short_description = _("Send test message in bulk")

	def enable(self, request, queryset):
		queryset.update(active=True)
	enable.short_description = _("Enable selected devices")

	def disable(self, request, queryset):
		queryset.update(active=False)
	disable.short_description = _("Disable selected devices")

	def prune_devices(self, request, queryset):
		# Note that when get_expired_tokens() is called, Apple's
		# feedback service resets, so, calling it again won't return
		# the device again (unless a message is sent to it again).  So,
		# if the user doesn't select all the devices for pruning, we
		# could very easily leave an expired device as active.  Maybe
		#  this is just a bad API.
		expired = get_expired_tokens()
		devices = queryset.filter(registration_id__in=expired)
		for d in devices:
			d.active = False
			d.save()


class APNDeviceAdmin(DeviceAdmin):

	def get_actions(self, request):
		# get the default actions
		actions = super(APNDeviceAdmin, self).get_actions(request)
		app_names = apns_get_app_names()
		if not app_names:
			return actions

		# in case of multiple apps defined, we remove the default `send_message` and `send_bulk_message`
		if "send_message" in actions:
			del actions["send_message"]
		if "send_bulk_message" in actions:
			del actions["send_bulk_message"]

		# and replace it with specific app actions
		for app_name in app_names:
			action_key = "send_message_{}".format(slugify(app_name))
			actions[action_key] = (
				lambda modeladmin, req, queryset, captured_app_name=app_name: modeladmin.send_messages(req, queryset, app_name=captured_app_name),
				action_key,
				_("Send test message [{}]").format(app_name),
			)

		return actions


class GCMDeviceAdmin(DeviceAdmin):
	pass


admin.site.register(APNSDevice, APNDeviceAdmin)
admin.site.register(GCMDevice, GCMDeviceAdmin)
